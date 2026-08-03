//! Java package analyzer

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use zip::ZipArchive;

use crate::core::{
    AnalysisResult, DependencyAnalysis, MaliciousPattern, PackageAnalyzer, PackageInfo,
    PackageMetadata, RiskAssessment, RiskCalculator, SupplyChainSignal, Vulnerability,
};

/// Java package information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaPackage {
    pub metadata: PackageMetadata,
    pub archive_type: JavaArchiveType,
    pub main_class: Option<String>,
    pub manifest_attributes: BTreeMap<String, String>,
    /// Whether the archive contains a JAR-style signature block filename.
    /// This is a presence signal, not cryptographic verification.
    pub has_signature_block_entry: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JavaArchiveType {
    Jar,
    War,
    Ear,
    Apk,
    Aar,
}

impl PackageInfo for JavaPackage {
    fn metadata(&self) -> &PackageMetadata {
        &self.metadata
    }

    fn package_type(&self) -> &str {
        "java"
    }

    fn custom_attributes(&self) -> BTreeMap<String, serde_json::Value> {
        let mut attrs = BTreeMap::new();
        attrs.insert(
            "archive_type".to_string(),
            serde_json::json!(self.archive_type),
        );
        attrs.insert("main_class".to_string(), serde_json::json!(self.main_class));
        attrs.insert(
            "has_signature_block_entry".to_string(),
            serde_json::json!(self.has_signature_block_entry),
        );
        attrs
    }
}

/// Java analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaAnalysisResult {
    pub package: JavaPackage,
    pub risk_assessment: RiskAssessment,
    pub dependency_analysis: DependencyAnalysis,
    pub vulnerabilities: Vec<Vulnerability>,
    pub malicious_patterns: Vec<MaliciousPattern>,
    pub security_analysis: JavaSecurityAnalysis,
    pub vulnerability_database: Option<crate::core::DatabaseMetadata>,
}

impl AnalysisResult for JavaAnalysisResult {
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

    fn malicious_patterns(&self) -> &[MaliciousPattern] {
        &self.malicious_patterns
    }

    fn vulnerability_database_metadata(&self) -> Option<&crate::core::DatabaseMetadata> {
        self.vulnerability_database.as_ref()
    }

    fn to_json(&self) -> Result<serde_json::Value> {
        Ok(serde_json::to_value(self)?)
    }
}

/// Java-specific security analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaSecurityAnalysis {
    pub has_native_libraries: bool,
}

/// Java package analyzer
pub struct JavaAnalyzer;

impl JavaAnalyzer {
    /// Create a new Java analyzer
    pub fn new() -> Result<Self> {
        Ok(Self)
    }

    /// Detect archive type from file extension
    fn detect_archive_type(path: &Path) -> Option<JavaArchiveType> {
        match path.extension().and_then(|e| e.to_str()) {
            Some(ext) if ext.eq_ignore_ascii_case("jar") => Some(JavaArchiveType::Jar),
            Some(ext) if ext.eq_ignore_ascii_case("war") => Some(JavaArchiveType::War),
            Some(ext) if ext.eq_ignore_ascii_case("ear") => Some(JavaArchiveType::Ear),
            Some(ext) if ext.eq_ignore_ascii_case("apk") => Some(JavaArchiveType::Apk),
            Some(ext) if ext.eq_ignore_ascii_case("aar") => Some(JavaArchiveType::Aar),
            _ => None,
        }
    }

    /// Inspect a Java archive without extracting it.
    fn inspect_archive(path: &Path) -> Result<(JavaPackage, JavaSecurityAnalysis)> {
        let archive_type = Self::detect_archive_type(path)
            .ok_or_else(|| anyhow::anyhow!("unsupported Java archive extension"))?;
        let metadata = std::fs::symlink_metadata(path)
            .with_context(|| format!("failed to inspect Java archive {path:?}"))?;
        if metadata.file_type().is_symlink() {
            bail!("refusing symlinked Java archive: {path:?}");
        }
        if !metadata.is_file() {
            bail!("Java archive is not a regular file: {path:?}");
        }
        if metadata.len() > crate::limits::MAX_ARCHIVE_BYTES {
            bail!(
                "Java archive exceeds the {}-byte compressed-size limit",
                crate::limits::MAX_ARCHIVE_BYTES
            );
        }

        let file = std::fs::File::open(path)
            .with_context(|| format!("failed to open Java archive {path:?}"))?;
        let opened_metadata = file.metadata()?;
        if !same_file_identity(&metadata, &opened_metadata) {
            bail!("Java archive changed while it was being opened");
        }
        if opened_metadata.len() > crate::limits::MAX_ARCHIVE_BYTES
            || opened_metadata.len() != metadata.len()
        {
            bail!("Java archive changed size while it was being opened");
        }
        let mut file = file;
        preflight_zip_directory(&mut file, opened_metadata.len())?;
        let final_identity_handle = file.try_clone()?;
        let mut archive = ZipArchive::new(file).context("invalid Java ZIP archive")?;
        if archive.len() > crate::limits::MAX_ARCHIVE_ENTRIES {
            bail!(
                "Java archive exceeds the {}-entry limit",
                crate::limits::MAX_ARCHIVE_ENTRIES
            );
        }

        let mut manifest_index = None;
        let mut has_signature_block_entry = false;
        let mut total_uncompressed = 0u64;
        let mut security_analysis = JavaSecurityAnalysis {
            has_native_libraries: false,
        };

        for i in 0..archive.len() {
            let file = archive.by_index(i)?;
            let name = file.name();
            if name.len() > crate::limits::MAX_ARCHIVE_ENTRY_NAME_BYTES {
                bail!("Java archive contains an overlong entry name");
            }
            if is_unsafe_archive_entry_name(name) || file.enclosed_name().is_none() {
                bail!("Java archive contains an unsafe entry path");
            }
            if file.is_symlink() {
                bail!("Java archive contains a symbolic-link entry");
            }
            if file.encrypted() {
                bail!("encrypted Java archive entries are unsupported");
            }
            if file.size() > crate::limits::MAX_ARCHIVE_ENTRY_BYTES {
                bail!("Java archive entry exceeds the configured uncompressed-size limit");
            }
            total_uncompressed = total_uncompressed
                .checked_add(file.size())
                .ok_or_else(|| anyhow::anyhow!("Java archive size accounting overflow"))?;
            if total_uncompressed > crate::limits::MAX_ARCHIVE_TOTAL_UNCOMPRESSED_BYTES {
                bail!("Java archive exceeds the aggregate uncompressed-size limit");
            }

            if name == "META-INF/MANIFEST.MF" {
                if manifest_index.replace(i).is_some() {
                    bail!("Java archive contains duplicate manifests");
                }
                if file.size() > crate::limits::MAX_MANIFEST_BYTES {
                    bail!("Java manifest exceeds the configured size limit");
                }
            }
            let lowercase_name = name.to_ascii_lowercase();
            if let Some(signature_name) = lowercase_name.strip_prefix("meta-inf/")
                && !signature_name.contains('/')
                && signature_name
                    .rsplit_once('.')
                    .is_some_and(|(base, extension)| {
                        !base.is_empty() && matches!(extension, "rsa" | "dsa" | "ec")
                    })
            {
                has_signature_block_entry = true;
            }
            if !file.is_dir()
                && (lowercase_name.ends_with(".so")
                    || lowercase_name.ends_with(".dll")
                    || lowercase_name.ends_with(".dylib"))
            {
                security_analysis.has_native_libraries = true;
            }
        }

        let manifest_attributes = if let Some(index) = manifest_index {
            let mut manifest = archive.by_index(index)?;
            let mut bytes = Vec::with_capacity(usize::try_from(manifest.size()).unwrap_or(0));
            manifest
                .by_ref()
                .take(crate::limits::MAX_MANIFEST_BYTES.saturating_add(1))
                .read_to_end(&mut bytes)?;
            if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > crate::limits::MAX_MANIFEST_BYTES {
                bail!("Java manifest exceeds the configured size limit");
            }
            let content = String::from_utf8(bytes).context("Java manifest is not valid UTF-8")?;
            parse_manifest(&content)?
        } else {
            BTreeMap::new()
        };
        let final_metadata = final_identity_handle.metadata()?;
        if !same_file_identity(&opened_metadata, &final_metadata)
            || final_metadata.len() != opened_metadata.len()
        {
            bail!("Java archive changed during analysis");
        }

        let main_class = manifest_attributes.get("main-class").cloned();

        // Extract metadata
        let metadata = PackageMetadata {
            name: path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string(),
            version: manifest_attributes
                .get("implementation-version")
                .or_else(|| manifest_attributes.get("bundle-version"))
                .cloned()
                .unwrap_or_else(|| "unknown".to_string()),
            description: manifest_attributes
                .get("bundle-description")
                .or_else(|| manifest_attributes.get("implementation-title"))
                .cloned(),
            author: manifest_attributes
                .get("implementation-vendor")
                .or_else(|| manifest_attributes.get("bundle-vendor"))
                .cloned(),
            license: manifest_attributes.get("bundle-license").cloned(),
            homepage: manifest_attributes.get("bundle-docurl").cloned(),
            repository: None,
            keywords: vec![],
            publish_date: None,
        };
        validate_java_metadata(&metadata)?;

        Ok((
            JavaPackage {
                metadata,
                archive_type,
                main_class,
                manifest_attributes,
                has_signature_block_entry,
            },
            security_analysis,
        ))
    }
}

#[async_trait]
impl PackageAnalyzer for JavaAnalyzer {
    type Package = JavaPackage;
    type Analysis = JavaAnalysisResult;

    async fn analyze(&self, path: &Path) -> Result<Self::Analysis> {
        crate::utils::require_tokio_runtime()?;
        let archive_path = path.to_path_buf();
        let (package, security_analysis) =
            tokio::task::spawn_blocking(move || Self::inspect_archive(&archive_path))
                .await
                .context("Java archive inspection task failed")??;
        let dependency_analysis = DependencyAnalysis::default();

        // Manifest values are metadata, not executable code. Bytecode inspection
        // is outside this analyzer's current capability boundary.
        let malicious_patterns = vec![];

        let mut vulnerabilities = vec![];
        for dep in &dependency_analysis.dependency_tree {
            vulnerabilities.extend(dep.vulnerabilities.clone());
        }

        // Calculate risk assessment
        let risk_calculator = RiskCalculator::new();
        let supply_chain_signal = if security_analysis.has_native_libraries {
            Some(SupplyChainSignal {
                score: 30.0,
                description: "Native library entries detected".to_string(),
                evidence: vec!["Archive contains .so, .dll, or .dylib entries".to_string()],
                mitigation: Some(
                    "Review native binaries for the target platforms before deployment".to_string(),
                ),
            })
        } else {
            None
        };

        let risk_score = risk_calculator.calculate(
            &vulnerabilities,
            &malicious_patterns,
            // Archive filenames do not establish authoritative Maven coordinates.
            false,
            supply_chain_signal,
            50.0, // Default maintenance score
        )?;

        let risk_assessment = RiskAssessment {
            risk_score: risk_score.clone(),
            summary: format!(
                "Java archive '{}' has {} risk",
                package.metadata.name.escape_default(),
                risk_score.risk_level
            ),
            detailed_findings: vec![],
            recommendations: vec![],
            security_posture: crate::core::SecurityPosture {
                vulnerability_matches_present: !vulnerabilities.is_empty(),
                high_severity_pattern_matches_present: false,
                supply_chain_risks: security_analysis.has_native_libraries,
                actively_maintained: None,
                // Signature blocks are only detected, never cryptographically
                // verified or tied to a trusted identity.
                trusted_publisher: None,
                security_practices_score: None,
            },
        };

        Ok(JavaAnalysisResult {
            package,
            risk_assessment,
            dependency_analysis,
            vulnerabilities,
            malicious_patterns,
            security_analysis,
            vulnerability_database: None,
        })
    }

    fn can_analyze(&self, path: &Path) -> bool {
        std::fs::symlink_metadata(path).is_ok_and(|metadata| {
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| {
                        ["jar", "war", "ear", "apk", "aar"]
                            .iter()
                            .any(|supported| ext.eq_ignore_ascii_case(supported))
                    })
                    .unwrap_or(false)
        })
    }

    fn name(&self) -> &str {
        "Java Package Analyzer"
    }

    fn supported_extensions(&self) -> Vec<&str> {
        vec!["jar", "war", "ear", "apk", "aar"]
    }
}

fn parse_manifest(content: &str) -> Result<BTreeMap<String, String>> {
    let mut attributes: BTreeMap<String, String> = BTreeMap::new();
    let mut current_key: Option<String> = None;

    let normalized = content.replace("\r\n", "\n").replace('\r', "\n");
    for (line_number, line) in normalized.lines().enumerate() {
        if line.is_empty() {
            break;
        }
        if line.len() > 72 || line.contains('\0') {
            bail!("Java manifest contains an invalid physical line");
        }
        if let Some(continuation) = line.strip_prefix(' ') {
            let key = current_key
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Java manifest starts with a continuation line"))?;
            let value = attributes
                .get_mut(key)
                .ok_or_else(|| anyhow::anyhow!("invalid Java manifest continuation"))?;
            value.push_str(continuation);
            if value.len() > crate::limits::MAX_METADATA_FIELD_BYTES {
                bail!("Java manifest attribute exceeds the configured size limit");
            }
            continue;
        }

        let (key, value) = line
            .split_once(": ")
            .ok_or_else(|| anyhow::anyhow!("invalid Java manifest attribute"))?;
        if line_number == 0 && (key != "Manifest-Version" || !valid_manifest_version(value)) {
            bail!("Java manifest has no valid leading Manifest-Version attribute");
        }
        if key.is_empty()
            || key.len() > 70
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            bail!("invalid Java manifest attribute name");
        }
        if value.len() > crate::limits::MAX_METADATA_FIELD_BYTES {
            bail!("Java manifest attribute exceeds the configured size limit");
        }
        if attributes.len() == crate::limits::MAX_MANIFEST_ATTRIBUTES {
            bail!("Java manifest exceeds the configured attribute-count limit");
        }
        let key = key.to_ascii_lowercase();
        if attributes.insert(key.clone(), value.to_string()).is_some() {
            bail!("Java manifest contains a duplicate main attribute");
        }
        current_key = Some(key);
    }

    if !attributes.contains_key("manifest-version") {
        bail!("Java manifest has no valid leading Manifest-Version attribute");
    }
    Ok(attributes)
}

fn valid_manifest_version(value: &str) -> bool {
    value.split('.').all(|component| {
        !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn validate_java_metadata(metadata: &PackageMetadata) -> Result<()> {
    for value in [
        Some(metadata.name.as_str()),
        Some(metadata.version.as_str()),
        metadata.description.as_deref(),
        metadata.author.as_deref(),
        metadata.license.as_deref(),
        metadata.homepage.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if value.len() > crate::limits::MAX_METADATA_FIELD_BYTES {
            bail!("Java package metadata exceeds the configured field limit");
        }
    }
    Ok(())
}

fn is_unsafe_archive_entry_name(name: &str) -> bool {
    name.is_empty()
        || name.starts_with('/')
        || name.bytes().any(|byte| matches!(byte, b'\\' | b'\0'))
        || (name.len() >= 2
            && name.as_bytes()[0].is_ascii_alphabetic()
            && name.as_bytes()[1] == b':')
        || name
            .split('/')
            .any(|component| component == ".." || component == ".")
        || name.contains("//")
}

fn preflight_zip_directory(file: &mut std::fs::File, file_len: u64) -> Result<()> {
    const EOCD_MIN_BYTES: u64 = 22;
    const MAX_COMMENT_BYTES: u64 = u16::MAX as u64;
    if file_len < EOCD_MIN_BYTES {
        bail!("Java archive is too short to contain a ZIP directory");
    }
    let tail_len = file_len.min(EOCD_MIN_BYTES + MAX_COMMENT_BYTES);
    file.seek(SeekFrom::End(-i64::try_from(tail_len)?))?;
    let mut tail = vec![0u8; usize::try_from(tail_len)?];
    file.read_exact(&mut tail)?;

    let eocd_offset = (0..=tail.len() - EOCD_MIN_BYTES as usize)
        .rev()
        .find(|offset| {
            tail[*offset..].starts_with(b"PK\x05\x06")
                && read_u16(&tail[*offset + 20..*offset + 22]).is_some_and(|comment_len| {
                    *offset + EOCD_MIN_BYTES as usize + usize::from(comment_len) == tail.len()
                })
        })
        .ok_or_else(|| anyhow::anyhow!("Java archive has no valid ZIP end record"))?;
    let eocd = &tail[eocd_offset..eocd_offset + EOCD_MIN_BYTES as usize];
    let disk = read_u16(&eocd[4..6]).unwrap_or(u16::MAX);
    let directory_disk = read_u16(&eocd[6..8]).unwrap_or(u16::MAX);
    let entries_on_disk = read_u16(&eocd[8..10]).unwrap_or(u16::MAX);
    let entries = read_u16(&eocd[10..12]).unwrap_or(u16::MAX);
    let directory_size = read_u32(&eocd[12..16]).unwrap_or(u32::MAX);
    let directory_offset = read_u32(&eocd[16..20]).unwrap_or(u32::MAX);

    if disk != 0 || directory_disk != 0 || entries_on_disk != entries {
        bail!("multi-disk Java ZIP archives are unsupported");
    }
    if entries == u16::MAX || directory_size == u32::MAX || directory_offset == u32::MAX {
        bail!("ZIP64 Java archives are unsupported by the bounded preflight");
    }
    if usize::from(entries) > crate::limits::MAX_ARCHIVE_ENTRIES {
        bail!("Java archive exceeds the configured entry limit");
    }
    if u64::from(directory_size) > crate::limits::MAX_ARCHIVE_DIRECTORY_BYTES {
        bail!("Java ZIP central directory exceeds the configured size limit");
    }
    let directory_end = u64::from(directory_offset)
        .checked_add(u64::from(directory_size))
        .ok_or_else(|| anyhow::anyhow!("Java ZIP directory size overflow"))?;
    if directory_end > file_len {
        bail!("Java ZIP central directory lies outside the archive");
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(())
}

fn read_u16(bytes: &[u8]) -> Option<u16> {
    bytes.try_into().ok().map(u16::from_le_bytes)
}

fn read_u32(bytes: &[u8]) -> Option<u32> {
    bytes.try_into().ok().map(u32::from_le_bytes)
}

#[cfg(unix)]
fn same_file_identity(before: &std::fs::Metadata, opened: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    before.dev() == opened.dev() && before.ino() == opened.ino()
}

#[cfg(not(unix))]
fn same_file_identity(before: &std::fs::Metadata, opened: &std::fs::Metadata) -> bool {
    before.file_type() == opened.file_type() && before.len() == opened.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn write_zip(path: &Path, entries: Vec<(&str, Vec<u8>)>) {
        let file = std::fs::File::create(path).expect("create test archive");
        let mut writer = zip::ZipWriter::new(file);
        for (name, content) in entries {
            writer
                .start_file(name, SimpleFileOptions::default())
                .expect("start archive entry");
            writer.write_all(&content).expect("write archive entry");
        }
        writer.finish().expect("finish test archive");
    }

    #[test]
    fn valid_archive_parses_case_insensitive_manifest_and_continuation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("sample.JAR");
        write_zip(
            &path,
            vec![
                (
                    "META-INF/MANIFEST.MF",
                    b"Manifest-Version: 1.0\rimplementation-version: 1.2.\r 3\rMain-Class: example.Main\rCustom_Attr: accepted\r\rignored: value\r".to_vec(),
                ),
                ("META-INF/SIGNATURE.RSA", vec![1]),
                ("lib/native.SO", vec![1]),
            ],
        );

        let (package, security) = JavaAnalyzer::inspect_archive(&path).expect("inspect archive");
        assert_eq!(package.metadata.version, "1.2.3");
        assert_eq!(package.main_class.as_deref(), Some("example.Main"));
        assert_eq!(
            package
                .manifest_attributes
                .get("custom_attr")
                .map(String::as_str),
            Some("accepted")
        );
        assert!(package.has_signature_block_entry);
        assert!(security.has_native_libraries);
        assert!(!package.manifest_attributes.contains_key("ignored"));
    }

    #[tokio::test]
    async fn native_library_risk_evidence_does_not_claim_install_scripts() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("native.jar");
        write_zip(&path, vec![("lib/native.so", vec![1])]);

        let result = JavaAnalyzer::new()
            .expect("construct analyzer")
            .analyze(&path)
            .await
            .expect("analyze archive");
        let factor = result
            .risk_assessment
            .risk_score
            .factors
            .iter()
            .find(|factor| factor.category == crate::core::risk::RiskCategory::SupplyChain)
            .expect("supply-chain factor");
        assert!(factor.evidence.iter().any(|value| value.contains(".so")));
        assert!(
            factor
                .evidence
                .iter()
                .all(|value| !value.contains("Installation scripts"))
        );
    }

    #[test]
    fn nested_signature_like_file_is_not_a_signature_block_entry() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("nested.jar");
        write_zip(&path, vec![("META-INF/docs/example.RSA", vec![1])]);
        let (package, _) = JavaAnalyzer::inspect_archive(&path).expect("inspect archive");
        assert!(!package.has_signature_block_entry);
    }

    #[test]
    fn rejects_unsafe_paths_and_oversized_manifests() {
        let directory = tempfile::tempdir().expect("temporary directory");
        for (index, entry) in [
            "../../outside",
            "/etc/passwd",
            r"C:\temp\payload.dll",
            r"\\server\share\payload.dll",
        ]
        .into_iter()
        .enumerate()
        {
            let unsafe_path = directory.path().join(format!("unsafe-{index}.jar"));
            write_zip(&unsafe_path, vec![(entry, vec![1])]);
            assert!(
                JavaAnalyzer::inspect_archive(&unsafe_path)
                    .expect_err("unsafe path must fail")
                    .to_string()
                    .contains("unsafe entry path"),
                "accepted unsafe entry {entry:?}"
            );
        }

        let oversized_path = directory.path().join("oversized.jar");
        write_zip(
            &oversized_path,
            vec![(
                "META-INF/MANIFEST.MF",
                vec![b'a'; crate::limits::MAX_MANIFEST_BYTES as usize + 1],
            )],
        );
        assert!(
            JavaAnalyzer::inspect_archive(&oversized_path)
                .expect_err("oversized manifest must fail")
                .to_string()
                .contains("manifest")
        );
    }

    #[test]
    fn preflight_rejects_entry_count_before_zip_parser_allocation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("count.jar");
        let entries = u16::try_from(crate::limits::MAX_ARCHIVE_ENTRIES + 1)
            .expect("test limit fits ZIP32 count");
        let mut eocd = Vec::from(*b"PK\x05\x06");
        eocd.extend_from_slice(&0u16.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes());
        eocd.extend_from_slice(&entries.to_le_bytes());
        eocd.extend_from_slice(&entries.to_le_bytes());
        eocd.extend_from_slice(&0u32.to_le_bytes());
        eocd.extend_from_slice(&0u32.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes());
        std::fs::write(&path, eocd).expect("write synthetic EOCD");

        assert!(
            JavaAnalyzer::inspect_archive(&path)
                .expect_err("entry count must fail")
                .to_string()
                .contains("entry limit")
        );
    }

    #[test]
    fn manifest_keys_are_case_insensitive_and_duplicates_fail() {
        let error =
            parse_manifest("Manifest-Version: 1.0\nMain-Class: first\nmain-class: second\n")
                .expect_err("case-insensitive duplicate must fail");
        assert!(error.to_string().contains("duplicate"));
    }

    #[test]
    fn inspect_rejects_unsupported_extension_even_for_valid_zip() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("sample.zip");
        write_zip(&path, vec![("a", vec![1])]);
        assert!(
            JavaAnalyzer::inspect_archive(&path)
                .expect_err("extension must be enforced")
                .to_string()
                .contains("unsupported")
        );
    }
}
