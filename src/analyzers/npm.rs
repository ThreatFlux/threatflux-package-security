//! NPM package analyzer

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

use crate::core::{
    AnalysisResult, Dependency, DependencyAnalysis, DependencyType, MaliciousPattern,
    PackageAnalyzer, PackageInfo, PackageMetadata, PatternMatcher, RiskAssessment, RiskCalculator,
    SupplyChainSignal, Vulnerability,
};
use crate::utils::typosquatting::{PackageEcosystem, TyposquattingDetector};
use crate::vulnerability_db::VulnerabilityDatabase;

/// NPM package information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmPackage {
    pub metadata: PackageMetadata,
    pub main: Option<String>,
    pub scripts: BTreeMap<String, String>,
    pub engines: BTreeMap<String, String>,
    pub files: Vec<String>,
    pub private: bool,
}

impl PackageInfo for NpmPackage {
    fn metadata(&self) -> &PackageMetadata {
        &self.metadata
    }

    fn package_type(&self) -> &str {
        "npm"
    }

    fn custom_attributes(&self) -> BTreeMap<String, serde_json::Value> {
        let mut attrs = BTreeMap::new();
        attrs.insert("main".to_string(), serde_json::json!(self.main));
        attrs.insert("scripts".to_string(), serde_json::json!(self.scripts));
        attrs.insert("engines".to_string(), serde_json::json!(self.engines));
        attrs.insert("private".to_string(), serde_json::json!(self.private));
        attrs
    }
}

/// NPM analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmAnalysisResult {
    pub package: NpmPackage,
    pub risk_assessment: RiskAssessment,
    pub dependency_analysis: DependencyAnalysis,
    /// Advisory matches for the package being analyzed, excluding its
    /// dependencies.
    pub subject_vulnerabilities: Vec<Vulnerability>,
    /// Deterministic union of subject and dependency advisory matches.
    pub vulnerabilities: Vec<Vulnerability>,
    pub malicious_patterns: Vec<MaliciousPattern>,
    pub scripts_analysis: ScriptsAnalysis,
    pub typosquatting_risk: Option<TyposquattingRisk>,
    pub vulnerability_database: crate::core::DatabaseMetadata,
}

impl AnalysisResult for NpmAnalysisResult {
    fn package_info(&self) -> &dyn PackageInfo {
        &self.package
    }

    fn risk_assessment(&self) -> &RiskAssessment {
        &self.risk_assessment
    }

    fn dependency_analysis(&self) -> &DependencyAnalysis {
        &self.dependency_analysis
    }

    fn vulnerabilities(&self) -> &[Vulnerability] {
        &self.vulnerabilities
    }

    fn subject_vulnerabilities(&self) -> &[Vulnerability] {
        &self.subject_vulnerabilities
    }

    fn malicious_patterns(&self) -> &[MaliciousPattern] {
        &self.malicious_patterns
    }

    fn vulnerability_database_metadata(&self) -> Option<&crate::core::DatabaseMetadata> {
        Some(&self.vulnerability_database)
    }

    fn to_json(&self) -> Result<serde_json::Value> {
        Ok(serde_json::to_value(self)?)
    }

    fn typosquatting_risk(&self) -> Option<crate::core::TyposquattingRisk> {
        self.typosquatting_risk
            .as_ref()
            .map(|risk| crate::core::TyposquattingRisk {
                is_potential_typosquatting: risk.is_likely_typosquatting,
                similar_packages: risk.similar_packages.clone(),
                confidence_score: risk.confidence,
            })
    }
}

/// NPM-specific scripts analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptsAnalysis {
    pub has_install_scripts: bool,
    pub suspicious_scripts: Vec<SuspiciousScript>,
    pub external_downloads: Vec<String>,
    pub shell_commands: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousScript {
    pub script_name: String,
    pub reason: String,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TyposquattingRisk {
    pub is_likely_typosquatting: bool,
    pub similar_packages: Vec<String>,
    pub confidence: f32,
}

/// NPM package analyzer
pub struct NpmAnalyzer {
    vuln_db: Box<dyn VulnerabilityDatabase>,
    pattern_matcher: PatternMatcher,
    typo_detector: TyposquattingDetector,
}

impl NpmAnalyzer {
    /// Create a new NPM analyzer
    pub fn new() -> Result<Self> {
        Ok(Self {
            vuln_db: crate::vulnerability_db::create_npm_database(),
            pattern_matcher: PatternMatcher::new()?,
            typo_detector: TyposquattingDetector::for_ecosystem(PackageEcosystem::Npm),
        })
    }

    /// Create an analyzer using an application-provided vulnerability database.
    pub fn with_database(vulnerability_database: Box<dyn VulnerabilityDatabase>) -> Result<Self> {
        Ok(Self {
            vuln_db: vulnerability_database,
            pattern_matcher: PatternMatcher::new()?,
            typo_detector: TyposquattingDetector::for_ecosystem(PackageEcosystem::Npm),
        })
    }

    /// Parse package.json file
    async fn parse_package_json(&self, content: &str) -> Result<NpmPackage> {
        let json: Value = serde_json::from_str(content).context("Failed to parse package.json")?;

        let obj = json
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("package.json is not an object"))?;

        let name = obj
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("package.json is missing a string name"))?;
        let version = obj
            .get("version")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("package.json is missing a string version"))?;
        validate_metadata_scalar("name", name)?;
        validate_metadata_scalar("version", version)?;

        let metadata = PackageMetadata {
            name: name.to_string(),
            version: version.to_string(),
            description: optional_string(obj, "description")?,
            author: parse_author(obj.get("author"))?,
            license: optional_string(obj, "license")?,
            homepage: optional_string(obj, "homepage")?,
            repository: parse_repository(obj.get("repository"))?,
            keywords: parse_string_list(obj.get("keywords"), "keywords", true)?,
            publish_date: None,
        };

        validate_metadata(&metadata)?;
        let scripts = parse_string_map(obj.get("scripts"), "scripts")?;
        let engines = parse_string_map(obj.get("engines"), "engines")?;

        let files = parse_string_list(obj.get("files"), "files", false)?;
        if files.len() > crate::limits::MAX_METADATA_LIST_ITEMS
            || files
                .iter()
                .any(|file: &String| file.len() > crate::limits::MAX_METADATA_FIELD_BYTES)
        {
            anyhow::bail!("package files metadata exceeds the configured limit");
        }

        Ok(NpmPackage {
            metadata,
            main: optional_string(obj, "main")?,
            scripts,
            engines,
            files,
            private: match obj.get("private") {
                Some(value) => value
                    .as_bool()
                    .ok_or_else(|| anyhow::anyhow!("package.json private must be a boolean"))?,
                None => false,
            },
        })
    }

    /// Analyze dependencies
    async fn analyze_dependencies(&self, package_json: &Value) -> Result<DependencyAnalysis> {
        let mut analysis = DependencyAnalysis::default();
        let obj = package_json
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("package.json is not an object"))?;

        // Parse different dependency types
        let dep_types = [
            ("dependencies", DependencyType::Runtime),
            ("devDependencies", DependencyType::Development),
            ("peerDependencies", DependencyType::Peer),
            ("optionalDependencies", DependencyType::Optional),
        ];

        let mut dependency_count = 0usize;
        for (field, _) in &dep_types {
            if let Some(value) = obj.get(*field) {
                let dependencies = value
                    .as_object()
                    .ok_or_else(|| anyhow::anyhow!("package.json {field} must be an object"))?;
                dependency_count = dependency_count
                    .checked_add(dependencies.len())
                    .ok_or_else(|| anyhow::anyhow!("dependency count overflow"))?;
            }
        }
        if dependency_count > crate::limits::MAX_DIRECT_DEPENDENCIES {
            anyhow::bail!("dependency count exceeds the configured limit");
        }

        let mut unique_dependencies = BTreeMap::new();
        for (field, dep_type) in &dep_types {
            if let Some(deps) = obj.get(*field).and_then(Value::as_object) {
                for (name, version_spec) in deps {
                    let version_str = version_spec.as_str().ok_or_else(|| {
                        anyhow::anyhow!(
                            "dependency {} has a non-string requirement",
                            name.escape_default()
                        )
                    })?;
                    validate_metadata_scalar("dependency name", name)?;
                    validate_npm_package_name(name)?;
                    validate_metadata_scalar("dependency requirement", version_str)?;
                    let normalized_name = crate::utils::package_name::npm(name);
                    // npm defines optionalDependencies as overriding a same-name
                    // dependencies entry. Other roles remain distinct declarations.
                    if *field == "optionalDependencies" {
                        unique_dependencies.remove(&(normalized_name.clone(), "dependencies"));
                    }
                    unique_dependencies.insert(
                        (normalized_name, *field),
                        (name.clone(), version_str.to_string(), dep_type.clone()),
                    );
                }
            }
        }

        for (_, (name, version_spec, dependency_type)) in unique_dependencies {
            let is_exact =
                crate::utils::version_parser::parse_exact_npm_requirement(&version_spec).is_ok();
            if !is_exact {
                analysis
                    .unresolved_requirements
                    .push(format!("{name}@{version_spec}"));
            }
            // Application-provided databases own their requirement semantics;
            // the built-in snapshot independently enforces exact versions.
            let vulnerabilities = self
                .vuln_db
                .check_package(&name, &version_spec, "npm")
                .await?;
            analysis.dependency_tree.push(Dependency {
                name,
                version_spec,
                resolved_version: None,
                is_dev: Some(matches!(dependency_type, DependencyType::Development)),
                dependency_type,
                is_direct: Some(true),
                vulnerabilities,
                license: None,
                dependencies: vec![],
            });
        }
        analysis.direct_dependencies = analysis.dependency_tree.len();

        analysis.total_dependencies = analysis.dependency_tree.len();
        analysis.unresolved_requirements.sort();
        analysis.unresolved_requirements.dedup();

        analysis.rebuild_vulnerability_summary();

        Ok(analysis)
    }

    /// Analyze scripts for suspicious patterns
    fn analyze_scripts(&self, scripts: &BTreeMap<String, String>) -> ScriptsAnalysis {
        let mut analysis = ScriptsAnalysis {
            has_install_scripts: false,
            suspicious_scripts: vec![],
            external_downloads: vec![],
            shell_commands: vec![],
        };

        let install_hooks = ["preinstall", "install", "postinstall", "prepare"];

        for (name, content) in scripts {
            // Check for install scripts
            if install_hooks.contains(&name.as_str()) {
                analysis.has_install_scripts = true;
            }

            // Check for external downloads
            if contains_shell_command(content, &["curl", "wget"]) {
                analysis.external_downloads.push(content.clone());
                analysis.suspicious_scripts.push(SuspiciousScript {
                    script_name: name.clone(),
                    reason: "Downloads external content".to_string(),
                    risk_level: "High".to_string(),
                });
            }

            // Check for shell commands
            if contains_shell_command(content, &["sh", "bash", "zsh", "dash", "exec"])
                || content.contains(".exec(")
            {
                analysis.shell_commands.push(content.clone());
            }

            // Check for suspicious patterns
            if contains_function_call(content, "eval") || content.contains("new Function(") {
                analysis.suspicious_scripts.push(SuspiciousScript {
                    script_name: name.clone(),
                    reason: "Dynamic code execution".to_string(),
                    risk_level: "Critical".to_string(),
                });
            }
        }

        analysis
    }
}

#[async_trait]
impl PackageAnalyzer for NpmAnalyzer {
    type Package = NpmPackage;
    type Analysis = NpmAnalysisResult;

    async fn analyze(&self, path: &Path) -> Result<Self::Analysis> {
        crate::utils::require_tokio_runtime()?;
        if !path.is_dir() {
            anyhow::bail!("npm analysis currently supports project directories only");
        }
        let content = crate::utils::input::read_project_file(
            path,
            Path::new("package.json"),
            crate::limits::MAX_PROJECT_FILE_BYTES,
        )
        .await
        .context("failed to read package.json")?;

        let package = self.parse_package_json(&content).await?;
        let json_value: Value = serde_json::from_str(&content)?;

        // Analyze scripts
        let scripts_analysis = self.analyze_scripts(&package.scripts);

        // Package metadata such as homepages is not executable. Scan lifecycle
        // script bodies only to avoid treating ordinary metadata as code.
        let script_content = package
            .scripts
            .iter()
            .map(|(name, script)| format!("{name}: {script}"))
            .collect::<Vec<_>>()
            .join("\n");
        let malicious_patterns = self
            .pattern_matcher
            .scan(&script_content, Some("package.json#scripts"))?;

        let dependency_analysis = self.analyze_dependencies(&json_value).await?;
        let subject_vulnerabilities = self
            .vuln_db
            .check_package(&package.metadata.name, &package.metadata.version, "npm")
            .await?;

        // Check typosquatting
        let typosquatting_risk = if self.typo_detector.is_typosquatting(&package.metadata.name) {
            Some(TyposquattingRisk {
                is_likely_typosquatting: true,
                similar_packages: self.typo_detector.find_similar(&package.metadata.name),
                confidence: 0.8,
            })
        } else {
            None
        };

        // Collect all vulnerabilities
        let vulnerabilities = crate::core::dependency::deduplicate_vulnerabilities(
            subject_vulnerabilities
                .iter()
                .cloned()
                .chain(dependency_analysis.unique_vulnerabilities()),
        );

        // Calculate risk assessment
        let risk_calculator = RiskCalculator::new();
        let supply_chain_signal = if !scripts_analysis.suspicious_scripts.is_empty() {
            Some(SupplyChainSignal {
                score: 40.0,
                description: "Suspicious lifecycle script behavior detected".to_string(),
                evidence: scripts_analysis
                    .suspicious_scripts
                    .iter()
                    .take(crate::limits::MAX_EVIDENCE_PER_PATTERN)
                    .map(|script| {
                        format!(
                            "{}: {}",
                            script.script_name.escape_default(),
                            script.reason.escape_default()
                        )
                    })
                    .collect(),
                mitigation: Some("Review lifecycle scripts before installation".to_string()),
            })
        } else if scripts_analysis.has_install_scripts {
            Some(SupplyChainSignal {
                score: 10.0,
                description: "Lifecycle installation hook present".to_string(),
                evidence: vec![
                    "preinstall, install, postinstall, or prepare hook detected".to_string(),
                ],
                mitigation: Some("Review lifecycle scripts before installation".to_string()),
            })
        } else {
            None
        };

        let risk_score = risk_calculator.calculate(
            &vulnerabilities,
            &malicious_patterns,
            typosquatting_risk.is_some(),
            supply_chain_signal,
            50.0, // Default maintenance score
        )?;

        let risk_assessment = RiskAssessment {
            risk_score: risk_score.clone(),
            summary: format!(
                "NPM package '{}' has {} risk with {} advisory matches and {} heuristic pattern matches",
                package.metadata.name.escape_default(),
                risk_score.risk_level,
                vulnerabilities.len(),
                malicious_patterns.len()
            ),
            detailed_findings: vec![],
            recommendations: vec![],
            security_posture: crate::core::SecurityPosture {
                vulnerability_matches_present: !vulnerabilities.is_empty(),
                high_severity_pattern_matches_present: malicious_patterns.iter().any(|pattern| {
                    pattern.severity >= crate::core::patterns::PatternSeverity::High
                }),
                supply_chain_risks: scripts_analysis.has_install_scripts
                    || !scripts_analysis.suspicious_scripts.is_empty(),
                actively_maintained: None,
                trusted_publisher: None,
                security_practices_score: None,
            },
        };
        let vulnerability_database = self.vuln_db.metadata();

        Ok(NpmAnalysisResult {
            package,
            risk_assessment,
            dependency_analysis,
            subject_vulnerabilities,
            vulnerabilities,
            malicious_patterns,
            scripts_analysis,
            typosquatting_risk,
            vulnerability_database,
        })
    }

    fn can_analyze(&self, path: &Path) -> bool {
        crate::utils::input::has_regular_project_file(path, Path::new("package.json"))
    }

    fn name(&self) -> &str {
        "NPM Package Analyzer"
    }

    fn supported_extensions(&self) -> Vec<&str> {
        vec![]
    }
}

fn validate_metadata(metadata: &PackageMetadata) -> Result<()> {
    for (name, value) in [
        ("name", Some(metadata.name.as_str())),
        ("version", Some(metadata.version.as_str())),
        ("description", metadata.description.as_deref()),
        ("author", metadata.author.as_deref()),
        ("license", metadata.license.as_deref()),
        ("homepage", metadata.homepage.as_deref()),
        ("repository", metadata.repository.as_deref()),
    ] {
        if let Some(value) = value {
            validate_metadata_scalar(name, value)?;
        }
    }
    if metadata.keywords.len() > crate::limits::MAX_METADATA_LIST_ITEMS {
        anyhow::bail!("keyword count exceeds the configured limit");
    }
    for keyword in &metadata.keywords {
        validate_metadata_scalar("keyword", keyword)?;
    }
    validate_npm_package_name(&metadata.name)?;
    crate::utils::version_parser::parse_npm_subject_version(&metadata.version)
        .context("package.json version must be an exact SemVer version")?;
    Ok(())
}

fn validate_npm_package_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 214
        || name != name.trim()
        || !name.is_ascii()
        || name.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        anyhow::bail!("invalid npm package name");
    }

    let valid_component = |component: &str| {
        !component.is_empty()
            && !component.starts_with(['.', '_'])
            && component.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_' | b'.' | b'~')
            })
    };
    if let Some(scoped) = name.strip_prefix('@') {
        let Some((scope, package)) = scoped.split_once('/') else {
            anyhow::bail!("invalid scoped npm package name");
        };
        if package.contains('/') || !valid_component(scope) || !valid_component(package) {
            anyhow::bail!("invalid scoped npm package name");
        }
    } else if name.contains('/') || !valid_component(name) {
        anyhow::bail!("invalid npm package name");
    }
    Ok(())
}

fn validate_metadata_scalar(name: &str, value: &str) -> Result<()> {
    if value.len() > crate::limits::MAX_METADATA_FIELD_BYTES {
        anyhow::bail!("{name} exceeds the configured metadata field limit");
    }
    Ok(())
}

fn parse_string_map(value: Option<&Value>, field: &str) -> Result<BTreeMap<String, String>> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    let object = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("package.json {field} must be an object"))?;
    if object.len() > crate::limits::MAX_METADATA_LIST_ITEMS {
        anyhow::bail!("package.json {field} exceeds the configured item limit");
    }
    object
        .iter()
        .map(|(key, value)| {
            let value = value.as_str().ok_or_else(|| {
                anyhow::anyhow!(
                    "package.json {field}.{} must be a string",
                    key.escape_default()
                )
            })?;
            validate_metadata_scalar(field, key)?;
            validate_metadata_scalar(field, value)?;
            Ok((key.clone(), value.to_string()))
        })
        .collect()
}

fn optional_string(object: &serde_json::Map<String, Value>, field: &str) -> Result<Option<String>> {
    object
        .get(field)
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("package.json {field} must be a string"))
                .and_then(|value| {
                    validate_metadata_scalar(field, value)?;
                    Ok(value.to_string())
                })
        })
        .transpose()
}

fn parse_string_list(
    value: Option<&Value>,
    field: &str,
    allow_string: bool,
) -> Result<Vec<String>> {
    let Some(value) = value else {
        return Ok(vec![]);
    };
    if allow_string && let Some(value) = value.as_str() {
        validate_metadata_scalar(field, value)?;
        return Ok(vec![value.to_string()]);
    }
    let values = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("package.json {field} must be an array of strings"))?;
    if values.len() > crate::limits::MAX_METADATA_LIST_ITEMS {
        anyhow::bail!("package.json {field} exceeds the configured item limit");
    }
    values
        .iter()
        .map(|value| {
            let value = value
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("package.json {field} entries must be strings"))?;
            validate_metadata_scalar(field, value)?;
            Ok(value.to_string())
        })
        .collect()
}

fn parse_author(value: Option<&Value>) -> Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if let Some(author) = value.as_str() {
        validate_metadata_scalar("author", author)?;
        return Ok(Some(author.to_string()));
    }
    let object = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("package.json author must be a string or object"))?;
    let name = optional_string(object, "name")?;
    let email = optional_string(object, "email")?;
    let url = optional_string(object, "url")?;
    if name.is_none() && email.is_none() && url.is_none() {
        anyhow::bail!("package.json author object has no supported fields");
    }
    let author = [name, email, url]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" | ");
    validate_metadata_scalar("author", &author)?;
    Ok(Some(author))
}

fn parse_repository(value: Option<&Value>) -> Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if let Some(repository) = value.as_str() {
        validate_metadata_scalar("repository", repository)?;
        return Ok(Some(repository.to_string()));
    }
    let object = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("package.json repository must be a string or object"))?;
    let repository = object
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("package.json repository object needs a string url"))?;
    validate_metadata_scalar("repository", repository)?;
    Ok(Some(repository.to_string()))
}

fn contains_shell_command(script: &str, commands: &[&str]) -> bool {
    script
        .split(|character: char| {
            character.is_whitespace() || matches!(character, ';' | '|' | '&' | '(' | ')')
        })
        .map(|token| token.trim_matches(['\'', '"']))
        .filter(|token| !token.is_empty())
        .any(|token| {
            let executable = token.rsplit(['/', '\\']).next().unwrap_or(token);
            commands.iter().any(|command| {
                executable.eq_ignore_ascii_case(command)
                    || executable.eq_ignore_ascii_case(&format!("{command}.exe"))
            })
        })
}

fn contains_function_call(content: &str, function: &str) -> bool {
    content.match_indices(function).any(|(offset, _)| {
        let before = content[..offset].chars().next_back();
        let after = content[offset + function.len()..]
            .trim_start()
            .chars()
            .next();
        !before.is_some_and(|character| character.is_alphanumeric() || character == '_')
            && after == Some('(')
    })
}
