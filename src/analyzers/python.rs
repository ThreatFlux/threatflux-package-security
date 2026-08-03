//! Python package analyzer

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::core::{
    AnalysisResult, Dependency, DependencyAnalysis, DependencyType, MaliciousPattern,
    PackageAnalyzer, PackageInfo, PackageMetadata, PatternMatcher, RiskAssessment, RiskCalculator,
    SupplyChainSignal, Vulnerability,
};
use crate::utils::typosquatting::{PackageEcosystem, TyposquattingDetector};
use crate::vulnerability_db::VulnerabilityDatabase;

/// Python package information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PythonPackage {
    pub metadata: PackageMetadata,
}

impl PackageInfo for PythonPackage {
    fn metadata(&self) -> &PackageMetadata {
        &self.metadata
    }

    fn package_type(&self) -> &str {
        "python"
    }

    fn custom_attributes(&self) -> BTreeMap<String, serde_json::Value> {
        BTreeMap::new()
    }
}

/// Python analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PythonAnalysisResult {
    pub package: PythonPackage,
    pub risk_assessment: RiskAssessment,
    pub dependency_analysis: DependencyAnalysis,
    /// Advisory matches for the package being analyzed, excluding its
    /// dependencies.
    pub subject_vulnerabilities: Vec<Vulnerability>,
    /// Deterministic union of subject and dependency advisory matches.
    pub vulnerabilities: Vec<Vulnerability>,
    pub malicious_patterns: Vec<MaliciousPattern>,
    pub setup_analysis: SetupAnalysis,
    pub typosquatting_risk: Option<TyposquattingRisk>,
    pub vulnerability_database: crate::core::DatabaseMetadata,
}

impl AnalysisResult for PythonAnalysisResult {
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

/// Python setup.py analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupAnalysis {
    pub has_setup_py: bool,
    pub has_custom_commands: bool,
    pub dangerous_operations: Vec<String>,
    pub external_downloads: Vec<String>,
    pub code_execution_risk: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TyposquattingRisk {
    pub is_likely_typosquatting: bool,
    pub similar_packages: Vec<String>,
    pub confidence: f32,
}

/// Python package analyzer
pub struct PythonAnalyzer {
    vuln_db: Box<dyn VulnerabilityDatabase>,
    pattern_matcher: PatternMatcher,
    typo_detector: TyposquattingDetector,
}

impl PythonAnalyzer {
    /// Create a new Python analyzer
    pub fn new() -> Result<Self> {
        Ok(Self {
            vuln_db: crate::vulnerability_db::create_python_database(),
            pattern_matcher: PatternMatcher::new()?,
            typo_detector: TyposquattingDetector::for_ecosystem(PackageEcosystem::Python),
        })
    }

    /// Create an analyzer using an application-provided vulnerability database.
    pub fn with_database(vulnerability_database: Box<dyn VulnerabilityDatabase>) -> Result<Self> {
        Ok(Self {
            vuln_db: vulnerability_database,
            pattern_matcher: PatternMatcher::new()?,
            typo_detector: TyposquattingDetector::for_ecosystem(PackageEcosystem::Python),
        })
    }

    /// Parse setup.py or pyproject.toml
    async fn parse_package_metadata(&self, path: &Path) -> Result<PythonPackage> {
        if !path.is_dir() {
            anyhow::bail!("Python analysis currently supports project directories only");
        }

        let metadata = if std::fs::symlink_metadata(path.join("pyproject.toml")).is_ok() {
            let content = crate::utils::input::read_project_file(
                path,
                Path::new("pyproject.toml"),
                crate::limits::MAX_PROJECT_FILE_BYTES,
            )
            .await?;
            let document = parse_toml_document(&content, "pyproject.toml")?;
            if document.get("project").is_some() {
                self.parse_pyproject_document(&document)?
            } else {
                self.parse_legacy_metadata(path).await?
            }
        } else {
            self.parse_legacy_metadata(path).await?
        };

        validate_python_metadata(&metadata)?;
        Ok(PythonPackage { metadata })
    }

    async fn parse_legacy_metadata(&self, path: &Path) -> Result<PackageMetadata> {
        if std::fs::symlink_metadata(path.join("setup.cfg")).is_ok() {
            let content = crate::utils::input::read_project_file(
                path,
                Path::new("setup.cfg"),
                crate::limits::MAX_PROJECT_FILE_BYTES,
            )
            .await?;
            self.parse_setup_cfg(&content)
        } else if std::fs::symlink_metadata(path.join("setup.py")).is_ok() {
            let content = crate::utils::input::read_project_file(
                path,
                Path::new("setup.py"),
                crate::limits::MAX_PROJECT_FILE_BYTES,
            )
            .await?;
            self.parse_setup_py(&content)
        } else {
            anyhow::bail!("No supported Python project metadata found")
        }
    }

    /// Parse setup.py file
    fn parse_setup_py(&self, content: &str) -> Result<PackageMetadata> {
        let fields = extract_setup_literal_fields(content)?;
        let required = |field: &str| {
            fields
                .get(field)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("setup() has no static string {field} field"))
        };

        Ok(PackageMetadata {
            name: required("name")?,
            version: required("version")?,
            description: fields.get("description").cloned(),
            author: fields.get("author").cloned(),
            license: fields.get("license").cloned(),
            homepage: fields.get("url").cloned(),
            repository: None,
            // setup.py list expressions are not evaluated or executed.
            keywords: vec![],
            publish_date: None,
        })
    }

    fn parse_pyproject_document(&self, toml_value: &toml::Value) -> Result<PackageMetadata> {
        let project = toml_value
            .get("project")
            .and_then(toml::Value::as_table)
            .ok_or_else(|| anyhow::anyhow!("No [project] table in pyproject.toml"))?;

        Ok(PackageMetadata {
            name: project
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Missing project name"))?
                .to_string(),
            version: project
                .get("version")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Missing project version"))?
                .to_string(),
            description: optional_toml_string(project, "description")?,
            author: parse_pyproject_authors(project.get("authors"))?,
            license: parse_pyproject_license(project.get("license"))?,
            homepage: parse_project_url(project, "Homepage")?,
            repository: parse_project_url(project, "Repository")?,
            keywords: parse_toml_string_array(project.get("keywords"), "project.keywords")?,
            publish_date: None,
        })
    }

    /// Parse setup.cfg file
    fn parse_setup_cfg(&self, content: &str) -> Result<PackageMetadata> {
        // Simple INI-style parsing
        let mut metadata = PackageMetadata {
            name: String::new(),
            version: String::new(),
            description: None,
            author: None,
            license: None,
            homepage: None,
            repository: None,
            keywords: vec![],
            publish_date: None,
        };

        let mut in_metadata_section = false;
        let mut saw_metadata_section = false;
        let mut metadata_keys = BTreeSet::new();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.eq_ignore_ascii_case("[metadata]") {
                if saw_metadata_section {
                    anyhow::bail!("setup.cfg contains duplicate metadata sections");
                }
                saw_metadata_section = true;
                in_metadata_section = true;
                continue;
            }
            if trimmed.starts_with('[') {
                in_metadata_section = false;
            }

            if in_metadata_section && let Some((key, value)) = line.split_once('=') {
                let key = key.trim().to_ascii_lowercase();
                let value = value.trim();
                if !metadata_keys.insert(key.clone()) {
                    anyhow::bail!("setup.cfg contains a duplicate metadata option");
                }

                match key.as_str() {
                    "name" => metadata.name = value.to_string(),
                    "version" => metadata.version = value.to_string(),
                    "description" => metadata.description = Some(value.to_string()),
                    "author" => metadata.author = Some(value.to_string()),
                    "license" => metadata.license = Some(value.to_string()),
                    "url" => metadata.homepage = Some(value.to_string()),
                    _ => {}
                }
            }
        }

        if metadata.name.is_empty() || metadata.version.is_empty() {
            return Err(anyhow::anyhow!("Missing required metadata in setup.cfg"));
        }

        Ok(metadata)
    }

    /// Analyze setup.py for dangerous operations
    fn analyze_setup(&self, content: &str) -> SetupAnalysis {
        let mut analysis = SetupAnalysis {
            has_setup_py: true,
            has_custom_commands: false,
            dangerous_operations: vec![],
            external_downloads: vec![],
            code_execution_risk: false,
        };

        // Check for custom commands
        if contains_python_identifier(content, "cmdclass") {
            analysis.has_custom_commands = true;
            analysis
                .dangerous_operations
                .push("Custom setup commands detected".to_string());
        }

        // Check for dangerous operations
        let dangerous_patterns = [
            ("subprocess.run", "Process execution", true, true),
            ("subprocess.call", "Process execution", true, true),
            ("subprocess.check_call", "Process execution", true, true),
            ("subprocess.check_output", "Process execution", true, true),
            ("subprocess.Popen", "Process execution", true, true),
            ("os.system", "System command execution", true, true),
            ("exec", "Dynamic code execution", true, true),
            ("eval", "Code evaluation", true, true),
            ("__import__", "Dynamic imports", true, true),
            ("urllib", "Network access", false, false),
            ("requests", "HTTP requests", false, false),
        ];

        for (pattern, description, executes_code, requires_call) in &dangerous_patterns {
            let matched = if *requires_call {
                contains_python_function_call(content, pattern)
            } else {
                contains_python_identifier(content, pattern)
            };
            if matched {
                analysis.dangerous_operations.push(description.to_string());
                analysis.code_execution_risk |= executes_code;
            }
        }

        // Check for external downloads
        if contains_python_function_call(content, "urlopen")
            || contains_python_function_call(content, "requests.get")
        {
            analysis
                .external_downloads
                .push("External download detected".to_string());
        }

        analysis
    }

    /// Analyze dependencies
    async fn analyze_dependencies(&self, path: &Path) -> Result<DependencyAnalysis> {
        let mut analysis = DependencyAnalysis::default();
        let (requirements, source) = load_python_requirements(path).await?;
        if requirements.len() > crate::limits::MAX_DIRECT_DEPENDENCIES {
            anyhow::bail!("dependency count exceeds the configured limit");
        }

        let mut parsed_requirements = BTreeMap::new();
        for raw_requirement in requirements {
            let Some((name, version_spec, has_environment_marker)) =
                parse_python_requirement(&raw_requirement)
            else {
                analysis.unresolved_requirements.push(raw_requirement);
                continue;
            };
            if name.len() > crate::limits::MAX_METADATA_FIELD_BYTES
                || version_spec.len() > crate::limits::MAX_METADATA_FIELD_BYTES
            {
                anyhow::bail!("Python requirement exceeds the configured field limit");
            }
            let is_exact =
                crate::utils::version_parser::parse_exact_python_requirement(&version_spec).is_ok();
            if has_environment_marker || !is_exact {
                analysis
                    .unresolved_requirements
                    .push(raw_requirement.clone());
            }

            parsed_requirements
                .entry((
                    crate::utils::package_name::python(&name),
                    version_spec.clone(),
                    has_environment_marker,
                ))
                .or_insert((name, version_spec, has_environment_marker));
        }

        for (_, (name, version_spec, has_environment_marker)) in parsed_requirements {
            // Without an application-supplied target environment, a marker's
            // truth value is unknown. Do not strip it and turn a conditional
            // declaration into an unconditional advisory match.
            let vulns = if !has_environment_marker {
                // Application-provided databases own their requirement
                // semantics; the built-in snapshot independently enforces
                // exact PEP 440 versions.
                self.vuln_db
                    .check_package(&name, &version_spec, "python")
                    .await?
            } else {
                vec![]
            };

            let dependency = Dependency {
                name,
                version_spec,
                resolved_version: None,
                dependency_type: match source {
                    PythonRequirementSource::Pep621 => DependencyType::Runtime,
                    PythonRequirementSource::RequirementsFile => DependencyType::Unknown,
                },
                is_direct: match source {
                    PythonRequirementSource::Pep621 => Some(true),
                    PythonRequirementSource::RequirementsFile => None,
                },
                is_dev: match source {
                    PythonRequirementSource::Pep621 => Some(false),
                    PythonRequirementSource::RequirementsFile => None,
                },
                vulnerabilities: vulns,
                license: None,
                dependencies: vec![],
            };

            if dependency.is_direct == Some(true) {
                analysis.direct_dependencies += 1;
            }
            analysis.dependency_tree.push(dependency);
        }

        analysis.total_dependencies = analysis.dependency_tree.len();
        analysis.unresolved_requirements.sort();
        analysis.unresolved_requirements.dedup();

        analysis.rebuild_vulnerability_summary();

        Ok(analysis)
    }
}

#[async_trait]
impl PackageAnalyzer for PythonAnalyzer {
    type Package = PythonPackage;
    type Analysis = PythonAnalysisResult;

    async fn analyze(&self, path: &Path) -> Result<Self::Analysis> {
        crate::utils::require_tokio_runtime()?;
        let package = self.parse_package_metadata(path).await?;
        let setup_content = if std::fs::symlink_metadata(path.join("setup.py")).is_ok() {
            Some(
                crate::utils::input::read_project_file(
                    path,
                    Path::new("setup.py"),
                    crate::limits::MAX_PROJECT_FILE_BYTES,
                )
                .await?,
            )
        } else {
            None
        };
        let dependency_analysis = self.analyze_dependencies(path).await?;
        let subject_vulnerabilities = self
            .vuln_db
            .check_package(&package.metadata.name, &package.metadata.version, "python")
            .await?;

        let setup_code = setup_content
            .as_deref()
            .map(sanitize_python_source)
            .unwrap_or_default();
        let setup_analysis = if setup_content.is_some() {
            self.analyze_setup(&setup_code)
        } else {
            SetupAnalysis {
                has_setup_py: false,
                has_custom_commands: false,
                dangerous_operations: vec![],
                external_downloads: vec![],
                code_execution_risk: false,
            }
        };

        // Surface heuristic text-pattern matches.
        let malicious_patterns = self.pattern_matcher.scan(&setup_code, Some("setup.py"))?;

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
        let supply_chain_signal = if setup_analysis.code_execution_risk {
            Some(SupplyChainSignal {
                score: 50.0,
                description: "Executable setup.py behavior detected".to_string(),
                evidence: setup_analysis
                    .dangerous_operations
                    .iter()
                    .take(crate::limits::MAX_EVIDENCE_PER_PATTERN)
                    .cloned()
                    .collect(),
                mitigation: Some(
                    "Review setup.py in an isolated environment before use".to_string(),
                ),
            })
        } else if setup_analysis.has_custom_commands {
            Some(SupplyChainSignal {
                score: 15.0,
                description: "Custom setup.py command hooks detected".to_string(),
                evidence: vec!["setup() declares cmdclass".to_string()],
                mitigation: Some("Review custom build/install commands before use".to_string()),
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
                "Python package '{}' has {} risk with {} advisory matches",
                package.metadata.name.escape_default(),
                risk_score.risk_level,
                vulnerabilities.len()
            ),
            detailed_findings: vec![],
            recommendations: vec![],
            security_posture: crate::core::SecurityPosture {
                vulnerability_matches_present: !vulnerabilities.is_empty(),
                high_severity_pattern_matches_present: malicious_patterns.iter().any(|pattern| {
                    pattern.severity >= crate::core::patterns::PatternSeverity::High
                }),
                supply_chain_risks: setup_analysis.code_execution_risk
                    || setup_analysis.has_custom_commands,
                actively_maintained: None,
                trusted_publisher: None,
                security_practices_score: None,
            },
        };
        let vulnerability_database = self.vuln_db.metadata();

        Ok(PythonAnalysisResult {
            package,
            risk_assessment,
            dependency_analysis,
            subject_vulnerabilities,
            vulnerabilities,
            malicious_patterns,
            setup_analysis,
            typosquatting_risk,
            vulnerability_database,
        })
    }

    fn can_analyze(&self, path: &Path) -> bool {
        ["pyproject.toml", "setup.cfg", "setup.py"]
            .iter()
            .any(|file| crate::utils::input::has_regular_project_file(path, Path::new(file)))
    }

    fn name(&self) -> &str {
        "Python Package Analyzer"
    }

    fn supported_extensions(&self) -> Vec<&str> {
        vec![]
    }
}

fn validate_python_metadata(metadata: &PackageMetadata) -> Result<()> {
    for (field, value) in [
        ("name", Some(metadata.name.as_str())),
        ("version", Some(metadata.version.as_str())),
        ("description", metadata.description.as_deref()),
        ("author", metadata.author.as_deref()),
        ("license", metadata.license.as_deref()),
        ("homepage", metadata.homepage.as_deref()),
        ("repository", metadata.repository.as_deref()),
    ] {
        if let Some(value) = value
            && value.len() > crate::limits::MAX_METADATA_FIELD_BYTES
        {
            anyhow::bail!("Python package {field} exceeds the configured field limit");
        }
    }
    if metadata.name.trim().is_empty() || metadata.version.trim().is_empty() {
        anyhow::bail!("Python package name and version must not be empty");
    }
    if !is_python_identifier(&metadata.name) {
        anyhow::bail!("invalid Python distribution name");
    }
    if metadata.keywords.len() > crate::limits::MAX_METADATA_LIST_ITEMS
        || metadata
            .keywords
            .iter()
            .any(|value| value.len() > crate::limits::MAX_METADATA_FIELD_BYTES)
    {
        anyhow::bail!("Python package keywords exceed the configured limits");
    }
    crate::utils::version_parser::parse_python_subject_version(&metadata.version)
        .map_err(|_| anyhow::anyhow!("Python package version must be an exact PEP 440 version"))?;
    Ok(())
}

fn optional_toml_string(
    table: &toml::map::Map<String, toml::Value>,
    field: &str,
) -> Result<Option<String>> {
    table
        .get(field)
        .map(|value| {
            value
                .as_str()
                .map(String::from)
                .ok_or_else(|| anyhow::anyhow!("pyproject project.{field} must be a string"))
        })
        .transpose()
}

fn parse_toml_string_array(value: Option<&toml::Value>, field: &str) -> Result<Vec<String>> {
    let Some(value) = value else {
        return Ok(vec![]);
    };
    let array = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("{field} must be an array of strings"))?;
    if array.len() > crate::limits::MAX_METADATA_LIST_ITEMS {
        anyhow::bail!("{field} exceeds the configured item limit");
    }
    array
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(String::from)
                .ok_or_else(|| anyhow::anyhow!("{field} entries must be strings"))
        })
        .collect()
}

fn parse_pyproject_authors(value: Option<&toml::Value>) -> Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let authors = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("project.authors must be an array"))?;
    if authors.len() > crate::limits::MAX_METADATA_LIST_ITEMS {
        anyhow::bail!("project.authors exceeds the configured item limit");
    }
    let mut rendered = Vec::with_capacity(authors.len());
    for author in authors {
        let table = author
            .as_table()
            .ok_or_else(|| anyhow::anyhow!("project.authors entries must be tables"))?;
        let name = optional_toml_string(table, "name")?;
        let email = optional_toml_string(table, "email")?;
        if name.is_none() && email.is_none() {
            anyhow::bail!("project.authors entry has neither name nor email");
        }
        rendered.push(
            [name, email]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" | "),
        );
    }
    Ok((!rendered.is_empty()).then(|| rendered.join("; ")))
}

fn parse_pyproject_license(value: Option<&toml::Value>) -> Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if let Some(license) = value.as_str() {
        return Ok(Some(license.to_string()));
    }
    let table = value
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("project.license must be a string or table"))?;
    if let Some(text) = table.get("text").and_then(toml::Value::as_str) {
        return Ok(Some(text.to_string()));
    }
    if table.get("file").and_then(toml::Value::as_str).is_some() {
        // Do not follow another project-controlled path merely to label a
        // package. Preserve that the license is file-declared.
        return Ok(Some("file-declared".to_string()));
    }
    anyhow::bail!("project.license table needs a string text or file field")
}

fn parse_project_url(
    project: &toml::map::Map<String, toml::Value>,
    label: &str,
) -> Result<Option<String>> {
    let Some(urls) = project.get("urls") else {
        return Ok(None);
    };
    let urls = urls
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("project.urls must be a table"))?;
    let value = urls
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(label))
        .map(|(_, value)| value);
    value
        .map(|value| {
            value
                .as_str()
                .map(String::from)
                .ok_or_else(|| anyhow::anyhow!("project.urls values must be strings"))
        })
        .transpose()
}

#[derive(Clone, Copy)]
enum PythonRequirementSource {
    Pep621,
    RequirementsFile,
}

async fn load_python_requirements(path: &Path) -> Result<(Vec<String>, PythonRequirementSource)> {
    if std::fs::symlink_metadata(path.join("pyproject.toml")).is_ok() {
        let content = crate::utils::input::read_project_file(
            path,
            Path::new("pyproject.toml"),
            crate::limits::MAX_PROJECT_FILE_BYTES,
        )
        .await?;
        let document = parse_toml_document(&content, "pyproject.toml")?;
        let dependencies = document
            .get("project")
            .and_then(|project| project.get("dependencies"));
        if dependencies.is_some() {
            return Ok((
                parse_toml_string_array(dependencies, "project.dependencies")?,
                PythonRequirementSource::Pep621,
            ));
        }
    }

    if std::fs::symlink_metadata(path.join("requirements.txt")).is_ok() {
        let content = crate::utils::input::read_project_file(
            path,
            Path::new("requirements.txt"),
            crate::limits::MAX_PROJECT_FILE_BYTES,
        )
        .await?;
        let mut requirements = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let line = strip_python_requirement_comment(line).trim();
            if !line.is_empty() {
                if requirements.len() == crate::limits::MAX_DIRECT_DEPENDENCIES {
                    anyhow::bail!("dependency count exceeds the configured limit");
                }
                requirements.push(line.to_string());
            }
        }
        return Ok((requirements, PythonRequirementSource::RequirementsFile));
    }

    Ok((vec![], PythonRequirementSource::RequirementsFile))
}

fn parse_python_requirement(requirement: &str) -> Option<(String, String, bool)> {
    let (requirement, has_environment_marker) = requirement
        .split_once(';')
        .map_or((requirement, false), |(base, _)| (base, true));
    let requirement = requirement.trim();
    if requirement.is_empty() || requirement.starts_with('-') {
        return None;
    }

    let name_end = requirement
        .find(['[', '<', '>', '=', '!', '~', '@'])
        .unwrap_or(requirement.len());
    let name = requirement[..name_end].trim();
    if !is_python_identifier(name) {
        return None;
    }

    let after_name = &requirement[name_end..];
    let after_extras = if let Some(extras) = after_name.strip_prefix('[') {
        let closing = extras.find(']')?;
        if !extras[..closing]
            .split(',')
            .map(str::trim)
            .all(is_python_identifier)
        {
            return None;
        }
        &extras[closing + 1..]
    } else {
        after_name
    };
    let version_spec = after_extras.trim();
    let version_spec = if version_spec.is_empty() {
        "*"
    } else {
        version_spec
    };
    Some((
        name.to_string(),
        version_spec.to_string(),
        has_environment_marker,
    ))
}

fn strip_python_requirement_comment(line: &str) -> &str {
    line.char_indices()
        .find(|(index, character)| {
            *character == '#'
                && *index > 0
                && line[..*index]
                    .chars()
                    .next_back()
                    .is_some_and(char::is_whitespace)
        })
        .map_or(line, |(index, _)| &line[..index])
}

fn parse_toml_document(content: &str, label: &str) -> Result<toml::Value> {
    toml::from_str(content).map_err(|error: toml::de::Error| {
        error.span().map_or_else(
            || anyhow::anyhow!("{label} contains invalid TOML"),
            |span| {
                anyhow::anyhow!(
                    "{label} contains invalid TOML near byte range {}..{}",
                    span.start,
                    span.end
                )
            },
        )
    })
}

fn is_python_identifier(value: &str) -> bool {
    value
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn contains_python_identifier(content: &str, identifier: &str) -> bool {
    content.match_indices(identifier).any(|(offset, _)| {
        let before = content[..offset].chars().next_back();
        let after = content[offset + identifier.len()..].chars().next();
        !before.is_some_and(|character| character.is_alphanumeric() || character == '_')
            && !after.is_some_and(|character| character.is_alphanumeric() || character == '_')
    })
}

fn contains_python_function_call(content: &str, function: &str) -> bool {
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

fn extract_setup_literal_fields(content: &str) -> Result<BTreeMap<String, String>> {
    const SUPPORTED_FIELDS: [&str; 6] =
        ["name", "version", "description", "author", "license", "url"];

    let code = sanitize_python_source(content);
    let bytes = code.as_bytes();
    let mut candidates = Vec::new();
    let mut search_from = 0usize;

    while let Some(relative) = code[search_from..].find("setup") {
        let start = search_from + relative;
        let end = start + "setup".len();
        search_from = end;
        if start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_') {
            continue;
        }
        if bytes
            .get(end)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            continue;
        }
        if previous_identifier(&code[..start]).as_deref() == Some("def") {
            continue;
        }

        let open = skip_ascii_whitespace(bytes, end);
        if bytes.get(open) != Some(&b'(') {
            continue;
        }
        let Some(close) = matching_call_parenthesis(bytes, open) else {
            anyhow::bail!("setup.py contains an unterminated setup() call");
        };
        search_from = close.saturating_add(1);

        let mut fields = BTreeMap::new();
        for field in SUPPORTED_FIELDS {
            if let Some(value) = find_setup_keyword_literal(content, &code, open, close, field)? {
                fields.insert(field.to_string(), value);
            }
        }
        if fields.contains_key("name") && fields.contains_key("version") {
            candidates.push(fields);
        }
    }

    match candidates.len() {
        1 => Ok(candidates.pop().unwrap_or_default()),
        0 => anyhow::bail!("setup.py has no unambiguous setup() call with static name and version"),
        _ => anyhow::bail!("setup.py has multiple setup() calls with static name and version"),
    }
}

fn previous_identifier(value: &str) -> Option<String> {
    let value = value.trim_end();
    let start = value
        .rfind(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .map_or(0, |index| index + 1);
    (!value[start..].is_empty()).then(|| value[start..].to_string())
}

fn matching_call_parenthesis(bytes: &[u8], open: usize) -> Option<usize> {
    let mut parenthesis_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    for (index, byte) in bytes.iter().copied().enumerate().skip(open) {
        match byte {
            b'(' => parenthesis_depth = parenthesis_depth.checked_add(1)?,
            b')' if parenthesis_depth == 1 && bracket_depth == 0 && brace_depth == 0 => {
                return Some(index);
            }
            b')' => parenthesis_depth = parenthesis_depth.checked_sub(1)?,
            b'[' => bracket_depth = bracket_depth.checked_add(1)?,
            b']' => bracket_depth = bracket_depth.checked_sub(1)?,
            b'{' => brace_depth = brace_depth.checked_add(1)?,
            b'}' => brace_depth = brace_depth.checked_sub(1)?,
            _ => {}
        }
    }
    None
}

fn find_setup_keyword_literal(
    raw: &str,
    code: &str,
    open: usize,
    close: usize,
    field: &str,
) -> Result<Option<String>> {
    let bytes = code.as_bytes();
    let mut parenthesis_depth = 1usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut found = None;
    let mut index = open + 1;

    while index < close {
        match bytes[index] {
            b'(' => parenthesis_depth += 1,
            b')' => parenthesis_depth = parenthesis_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b'{' => brace_depth += 1,
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            _ => {}
        }

        if parenthesis_depth == 1
            && bracket_depth == 0
            && brace_depth == 0
            && bytes[index..].starts_with(field.as_bytes())
            && (index == open + 1
                || !(bytes[index - 1].is_ascii_alphanumeric() || bytes[index - 1] == b'_'))
            && bytes
                .get(index + field.len())
                .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
        {
            let equals = skip_ascii_whitespace(bytes, index + field.len());
            if bytes.get(equals) == Some(&b'=') && bytes.get(equals + 1) != Some(&b'=') {
                let value_start = skip_ascii_whitespace(raw.as_bytes(), equals + 1);
                let Some((value, literal_end)) = parse_static_python_string(raw, value_start)
                else {
                    anyhow::bail!("setup() {field} must be a simple static string literal");
                };
                let value_end = skip_ascii_whitespace(bytes, literal_end);
                if value_end > close
                    || !only_python_spacing_or_comments(&raw[literal_end..value_end])
                    || !matches!(bytes.get(value_end), Some(b',') | Some(b')'))
                {
                    anyhow::bail!("setup() {field} must be exactly one static string literal");
                }
                if found.replace(value).is_some() {
                    anyhow::bail!("setup() contains duplicate {field} fields");
                }
            }
        }
        index += 1;
    }

    Ok(found)
}

fn skip_ascii_whitespace(bytes: &[u8], mut index: usize) -> usize {
    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    index
}

fn only_python_spacing_or_comments(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut in_comment = false;
    for byte in bytes {
        if in_comment {
            if matches!(byte, b'\n' | b'\r') {
                in_comment = false;
            }
        } else if *byte == b'#' {
            in_comment = true;
        } else if !byte.is_ascii_whitespace() {
            return false;
        }
    }
    true
}

fn parse_static_python_string(content: &str, start: usize) -> Option<(String, usize)> {
    let bytes = content.as_bytes();
    let mut quote_index = start;
    while bytes
        .get(quote_index)
        .is_some_and(|byte| byte.is_ascii_alphabetic())
    {
        quote_index += 1;
    }
    let prefix = content.get(start..quote_index)?.to_ascii_lowercase();
    if !matches!(prefix.as_str(), "" | "r" | "u" | "ru" | "ur") {
        return None;
    }
    let quote = *bytes.get(quote_index)?;
    if !matches!(quote, b'\'' | b'"')
        || bytes.get(quote_index + 1) == Some(&quote)
        || bytes.get(quote_index + 2) == Some(&quote)
    {
        return None;
    }
    let mut index = quote_index + 1;
    while let Some(byte) = bytes.get(index).copied() {
        if byte == quote {
            return Some((content[quote_index + 1..index].to_string(), index + 1));
        }
        // Reject escapes instead of guessing at Python literal semantics.
        if byte == b'\\' || matches!(byte, b'\n' | b'\r') {
            return None;
        }
        index += 1;
    }
    None
}

#[derive(Clone, Copy)]
enum PythonLexState {
    Code,
    Comment,
    String {
        quote: u8,
        triple: bool,
        formatted: bool,
    },
    FormattedExpression {
        brace_depth: usize,
    },
}

/// Remove comments and string contents while preserving executable tokens and
/// line boundaries. This is a lexical filter, not Python execution or an AST.
fn sanitize_python_source(content: &str) -> String {
    let bytes = content.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut states = vec![PythonLexState::Code];
    let mut index = 0usize;

    while index < bytes.len() {
        match *states.last().unwrap_or(&PythonLexState::Code) {
            PythonLexState::Code => match bytes[index] {
                b'#' => {
                    output.push(b' ');
                    index += 1;
                    states.push(PythonLexState::Comment);
                }
                quote @ (b'\'' | b'"') => {
                    let triple = bytes.get(index + 1) == Some(&quote)
                        && bytes.get(index + 2) == Some(&quote);
                    let width = if triple { 3 } else { 1 };
                    output.extend(std::iter::repeat_n(b' ', width));
                    let formatted = has_formatted_string_prefix(bytes, index);
                    index += width;
                    states.push(PythonLexState::String {
                        quote,
                        triple,
                        formatted,
                    });
                }
                byte => {
                    output.push(byte);
                    index += 1;
                }
            },
            PythonLexState::Comment => {
                let byte = bytes[index];
                if matches!(byte, b'\n' | b'\r') {
                    output.push(byte);
                    states.pop();
                } else {
                    output.push(b' ');
                }
                index += 1;
            }
            PythonLexState::String {
                quote,
                triple,
                formatted,
            } => {
                if bytes[index] == b'\\' {
                    output.push(b' ');
                    index += 1;
                    if let Some(byte) = bytes.get(index).copied() {
                        output.push(if matches!(byte, b'\n' | b'\r') {
                            byte
                        } else {
                            b' '
                        });
                        index += 1;
                    }
                } else if triple
                    && bytes.get(index) == Some(&quote)
                    && bytes.get(index + 1) == Some(&quote)
                    && bytes.get(index + 2) == Some(&quote)
                {
                    output.extend_from_slice(b"   ");
                    index += 3;
                    states.pop();
                } else if !triple && bytes[index] == quote {
                    output.push(b' ');
                    index += 1;
                    states.pop();
                } else if formatted && bytes[index] == b'{' && bytes.get(index + 1) != Some(&b'{') {
                    output.push(b' ');
                    index += 1;
                    states.push(PythonLexState::FormattedExpression { brace_depth: 1 });
                } else if formatted
                    && matches!(bytes[index], b'{' | b'}')
                    && bytes.get(index + 1) == Some(&bytes[index])
                {
                    output.extend_from_slice(b"  ");
                    index += 2;
                } else {
                    let byte = bytes[index];
                    output.push(if matches!(byte, b'\n' | b'\r') {
                        byte
                    } else {
                        b' '
                    });
                    index += 1;
                }
            }
            PythonLexState::FormattedExpression { brace_depth } => match bytes[index] {
                b'#' => {
                    output.push(b' ');
                    index += 1;
                    states.push(PythonLexState::Comment);
                }
                quote @ (b'\'' | b'"') => {
                    let triple = bytes.get(index + 1) == Some(&quote)
                        && bytes.get(index + 2) == Some(&quote);
                    let width = if triple { 3 } else { 1 };
                    output.extend(std::iter::repeat_n(b' ', width));
                    let formatted = has_formatted_string_prefix(bytes, index);
                    index += width;
                    states.push(PythonLexState::String {
                        quote,
                        triple,
                        formatted,
                    });
                }
                b'{' => {
                    output.push(b'{');
                    index += 1;
                    if let Some(PythonLexState::FormattedExpression { brace_depth }) =
                        states.last_mut()
                    {
                        *brace_depth = brace_depth.saturating_add(1);
                    }
                }
                b'}' if brace_depth == 1 => {
                    output.push(b' ');
                    index += 1;
                    states.pop();
                }
                b'}' => {
                    output.push(b'}');
                    index += 1;
                    if let Some(PythonLexState::FormattedExpression { brace_depth }) =
                        states.last_mut()
                    {
                        *brace_depth = brace_depth.saturating_sub(1);
                    }
                }
                byte => {
                    output.push(byte);
                    index += 1;
                }
            },
        }
    }

    String::from_utf8(output).unwrap_or_default()
}

fn has_formatted_string_prefix(bytes: &[u8], quote_index: usize) -> bool {
    let mut start = quote_index;
    while start > 0 && bytes[start - 1].is_ascii_alphabetic() {
        start -= 1;
    }
    if start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_') {
        return false;
    }
    matches!(
        bytes[start..quote_index]
            .iter()
            .map(u8::to_ascii_lowercase)
            .collect::<Vec<_>>()
            .as_slice(),
        b"f" | b"fr" | b"rf"
    )
}
