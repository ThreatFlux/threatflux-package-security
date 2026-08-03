//! Heuristic text-pattern detection framework.

use anyhow::{Result, bail};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Malicious pattern definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaliciousPattern {
    pub pattern_id: String,
    pub pattern_name: String,
    pub description: String,
    pub category: PatternCategory,
    pub severity: PatternSeverity,
    pub indicators: Vec<String>,
    pub regex_patterns: Vec<String>,
    pub file_patterns: Vec<String>,
    pub evidence: Vec<String>,
}

/// Pattern categories
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PatternCategory {
    CodeExecution,
    DataExfiltration,
    Backdoor,
    CryptoMining,
    Obfuscation,
    NetworkAccess,
    FileSystemAccess,
    PrivilegeEscalation,
    Persistence,
    AntiAnalysis,
}

/// Pattern severity
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum PatternSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Pattern matcher for surfacing heuristic text signals.
pub struct PatternMatcher {
    patterns: Vec<CompiledPattern>,
}

/// Compiled pattern with regex
struct CompiledPattern {
    pattern: MaliciousPattern,
    regex_matchers: Vec<Regex>,
}

impl PatternMatcher {
    /// Create a new pattern matcher with default patterns
    pub fn new() -> Result<Self> {
        Self::with_patterns(Self::default_patterns())
    }

    /// Create matcher with custom patterns
    pub fn with_patterns(patterns: Vec<MaliciousPattern>) -> Result<Self> {
        Self::validate_collection(&patterns)?;
        let compiled = patterns
            .into_iter()
            .map(Self::compile_pattern)
            .collect::<Result<Vec<_>>>()?;

        Ok(Self { patterns: compiled })
    }

    /// Compile a pattern
    fn compile_pattern(pattern: MaliciousPattern) -> Result<CompiledPattern> {
        let mut pattern = pattern;
        let regex_matchers = pattern
            .regex_patterns
            .iter()
            .map(|pattern| compile_regex(pattern))
            .collect::<Result<Vec<_>, _>>()?;
        pattern.evidence.clear();

        Ok(CompiledPattern {
            pattern,
            regex_matchers,
        })
    }

    /// Scan content for heuristic pattern matches.
    pub fn scan(&self, content: &str, file_path: Option<&str>) -> Result<Vec<MaliciousPattern>> {
        if content.len() > crate::limits::MAX_PATTERN_INPUT_BYTES {
            bail!(
                "pattern input exceeds the {}-byte limit",
                crate::limits::MAX_PATTERN_INPUT_BYTES
            );
        }
        if file_path.is_some_and(|path| path.len() > crate::limits::MAX_ARCHIVE_ENTRY_NAME_BYTES) {
            bail!("pattern file path exceeds the configured length limit");
        }

        let mut detected = Vec::new();
        let mut total_evidence = 0usize;

        for compiled in &self.patterns {
            let mut matches = false;
            let mut evidence = Vec::new();

            // Indicators are case-sensitive literal signals. They complement
            // regexes for callers that do not need pattern syntax.
            for indicator in &compiled.pattern.indicators {
                if let Some(offset) = content.find(indicator) {
                    matches = true;
                    if evidence.len() < crate::limits::MAX_EVIDENCE_PER_PATTERN
                        && total_evidence < crate::limits::MAX_TOTAL_EVIDENCE
                    {
                        evidence.push(format!(
                            "Indicator '{}' found at byte offset {offset}",
                            indicator.escape_default()
                        ));
                        total_evidence += 1;
                    }
                }
            }

            // Check regex patterns
            for regex in &compiled.regex_matchers {
                if let Some(m) = regex.find(content) {
                    matches = true;
                    if evidence.len() < crate::limits::MAX_EVIDENCE_PER_PATTERN
                        && total_evidence < crate::limits::MAX_TOTAL_EVIDENCE
                    {
                        evidence.push(format!(
                            "Pattern '{}' found at byte offset {}",
                            regex.as_str().escape_default(),
                            m.start()
                        ));
                        total_evidence += 1;
                    }
                }
            }

            // Check file patterns if path provided
            if let Some(path) = file_path {
                for file_pattern in &compiled.pattern.file_patterns {
                    if path.contains(file_pattern) {
                        matches = true;
                        if evidence.len() < crate::limits::MAX_EVIDENCE_PER_PATTERN
                            && total_evidence < crate::limits::MAX_TOTAL_EVIDENCE
                        {
                            evidence.push(format!(
                                "File pattern '{}' matched",
                                file_pattern.escape_default()
                            ));
                            total_evidence += 1;
                        }
                    }
                }
            }

            if matches {
                if detected.len() == crate::limits::MAX_DETECTED_PATTERNS {
                    bail!(
                        "detected patterns exceed the {}-finding limit",
                        crate::limits::MAX_DETECTED_PATTERNS
                    );
                }
                let mut pattern = compiled.pattern.clone();
                pattern.evidence = evidence;
                detected.push(pattern);
            }
        }

        Ok(detected)
    }

    fn validate_collection(patterns: &[MaliciousPattern]) -> Result<()> {
        if patterns.len() > crate::limits::MAX_CUSTOM_PATTERNS {
            bail!(
                "custom pattern count exceeds the {}-pattern limit",
                crate::limits::MAX_CUSTOM_PATTERNS
            );
        }

        let mut ids = BTreeSet::new();
        let mut total_regexes = 0usize;
        let mut total_regex_bytes = 0usize;
        let mut total_list_items = 0usize;
        let mut total_definition_bytes = 0usize;
        for pattern in patterns {
            if !pattern.evidence.is_empty() {
                bail!("pattern definition evidence must be empty");
            }
            if pattern.pattern_id.trim().is_empty()
                || pattern.pattern_id.len() > crate::limits::MAX_PATTERN_ID_BYTES
            {
                bail!(
                    "pattern IDs must contain 1 to {} bytes",
                    crate::limits::MAX_PATTERN_ID_BYTES
                );
            }
            if !ids.insert(pattern.pattern_id.as_str()) {
                bail!(
                    "duplicate pattern ID: {}",
                    pattern.pattern_id.escape_default()
                );
            }
            if pattern.pattern_name.len() > crate::limits::MAX_PATTERN_NAME_BYTES
                || pattern.description.len() > crate::limits::MAX_PATTERN_DESCRIPTION_BYTES
            {
                bail!("pattern metadata exceeds the configured length limit");
            }
            if pattern.regex_patterns.len() > crate::limits::MAX_REGEXES_PER_PATTERN {
                bail!(
                    "pattern {} exceeds the per-pattern regex limit",
                    pattern.pattern_id.escape_default()
                );
            }
            if pattern.indicators.len() > crate::limits::MAX_PATTERN_LIST_ITEMS
                || pattern.file_patterns.len() > crate::limits::MAX_PATTERN_LIST_ITEMS
            {
                bail!("pattern lists exceed the configured item limit");
            }
            if pattern
                .indicators
                .iter()
                .chain(&pattern.file_patterns)
                .any(|value| {
                    value.is_empty() || value.len() > crate::limits::MAX_PATTERN_LIST_VALUE_BYTES
                })
            {
                bail!("pattern list values must be non-empty and within the configured limit");
            }
            if pattern
                .regex_patterns
                .iter()
                .any(|regex| regex.is_empty() || regex.len() > crate::limits::MAX_REGEX_BYTES)
            {
                bail!(
                    "custom regular expressions must be non-empty and within the configured limit"
                );
            }
            for regex in &pattern.regex_patterns {
                compile_regex(regex).map_err(|error| {
                    anyhow::anyhow!(
                        "invalid regex in pattern {}: {error}",
                        pattern.pattern_id.escape_default()
                    )
                })?;
            }

            total_regexes = total_regexes
                .checked_add(pattern.regex_patterns.len())
                .ok_or_else(|| anyhow::anyhow!("custom regex count overflow"))?;
            total_regex_bytes =
                pattern
                    .regex_patterns
                    .iter()
                    .try_fold(total_regex_bytes, |total, regex| {
                        total
                            .checked_add(regex.len())
                            .ok_or_else(|| anyhow::anyhow!("custom regex byte count overflow"))
                    })?;
            total_list_items = total_list_items
                .checked_add(pattern.indicators.len())
                .and_then(|total| total.checked_add(pattern.file_patterns.len()))
                .ok_or_else(|| anyhow::anyhow!("pattern list item count overflow"))?;
            total_definition_bytes = pattern
                .indicators
                .iter()
                .chain(&pattern.file_patterns)
                .chain(&pattern.regex_patterns)
                .try_fold(
                    total_definition_bytes
                        .checked_add(pattern.pattern_id.len())
                        .and_then(|total| total.checked_add(pattern.pattern_name.len()))
                        .and_then(|total| total.checked_add(pattern.description.len()))
                        .ok_or_else(|| anyhow::anyhow!("pattern definition byte count overflow"))?,
                    |total, value| {
                        total.checked_add(value.len()).ok_or_else(|| {
                            anyhow::anyhow!("pattern definition byte count overflow")
                        })
                    },
                )?;
        }

        if total_regexes > crate::limits::MAX_TOTAL_REGEXES {
            bail!(
                "custom regex count exceeds the {}-regex aggregate limit",
                crate::limits::MAX_TOTAL_REGEXES
            );
        }
        if total_regex_bytes > crate::limits::MAX_TOTAL_REGEX_BYTES {
            bail!(
                "custom regex bytes exceed the {}-byte aggregate limit",
                crate::limits::MAX_TOTAL_REGEX_BYTES
            );
        }
        if total_list_items > crate::limits::MAX_TOTAL_PATTERN_LIST_ITEMS {
            bail!("pattern list items exceed the configured aggregate limit");
        }
        if total_definition_bytes > crate::limits::MAX_TOTAL_PATTERN_DEFINITION_BYTES {
            bail!("pattern definitions exceed the configured aggregate byte limit");
        }
        Ok(())
    }

    /// Get the default heuristic pattern definitions.
    fn default_patterns() -> Vec<MaliciousPattern> {
        vec![
            // Code execution patterns
            MaliciousPattern {
                pattern_id: "EXEC_001".to_string(),
                pattern_name: "Dynamic code execution".to_string(),
                description: "Detects dynamic code execution attempts".to_string(),
                category: PatternCategory::CodeExecution,
                severity: PatternSeverity::Critical,
                indicators: vec![],
                regex_patterns: vec![
                    r"\beval\s*\(".to_string(),
                    r"\bexec\s*\(".to_string(),
                    r"new\s+Function\s*\(".to_string(),
                    r"\bsubprocess\.(call|run|Popen)".to_string(),
                    r"\bos\.system\s*\(".to_string(),
                ],
                file_patterns: vec![],
                evidence: vec![],
            },
            // Backdoor patterns
            MaliciousPattern {
                pattern_id: "BACK_001".to_string(),
                pattern_name: "Reverse shell".to_string(),
                description: "Detects reverse shell patterns".to_string(),
                category: PatternCategory::Backdoor,
                severity: PatternSeverity::Critical,
                indicators: vec![],
                regex_patterns: vec![
                    r"\bnc\s+-[elvp]*e".to_string(),
                    r"\bbash\s+-i".to_string(),
                    r"/dev/tcp/".to_string(),
                ],
                file_patterns: vec![],
                evidence: vec![],
            },
            // Crypto mining patterns
            MaliciousPattern {
                pattern_id: "MINE_001".to_string(),
                pattern_name: "Cryptocurrency mining".to_string(),
                description: "Detects cryptocurrency mining code".to_string(),
                category: PatternCategory::CryptoMining,
                severity: PatternSeverity::High,
                indicators: vec![],
                regex_patterns: vec![
                    r"stratum\+tcp://".to_string(),
                    r"(monero|bitcoin|ethereum).*mining".to_string(),
                    r"coinhive|cryptoloot".to_string(),
                ],
                file_patterns: vec![],
                evidence: vec![],
            },
            // Obfuscation patterns
            MaliciousPattern {
                pattern_id: "OBFU_001".to_string(),
                pattern_name: "Base64 obfuscation".to_string(),
                description: "Detects base64 encoded/decoded content".to_string(),
                category: PatternCategory::Obfuscation,
                severity: PatternSeverity::Medium,
                indicators: vec![],
                regex_patterns: vec![
                    r"base64\.(b64)?decode".to_string(),
                    r"atob\s*\(".to_string(),
                    r#"Buffer\.from\([^,]+,\s*['"]base64"#.to_string(),
                ],
                file_patterns: vec![],
                evidence: vec![],
            },
            // Persistence patterns
            MaliciousPattern {
                pattern_id: "PERS_001".to_string(),
                pattern_name: "System persistence".to_string(),
                description: "Detects attempts to establish system persistence".to_string(),
                category: PatternCategory::Persistence,
                severity: PatternSeverity::High,
                indicators: vec![],
                regex_patterns: vec![
                    r"\.bashrc|\.profile|\.zshrc".to_string(),
                    r"crontab|systemd|systemctl".to_string(),
                ],
                file_patterns: vec![],
                evidence: vec![],
            },
            // Anti-analysis patterns
            MaliciousPattern {
                pattern_id: "ANTI_001".to_string(),
                pattern_name: "Anti-analysis".to_string(),
                description: "Detects anti-analysis and evasion techniques".to_string(),
                category: PatternCategory::AntiAnalysis,
                severity: PatternSeverity::Medium,
                indicators: vec![],
                regex_patterns: vec![
                    r"(?i)\b(debugger|ollydbg|ida|ghidra)\b".to_string(),
                    r"IsDebuggerPresent|CheckRemoteDebuggerPresent".to_string(),
                    r"ptrace.*PTRACE_TRACEME".to_string(),
                ],
                file_patterns: vec![],
                evidence: vec![],
            },
            // Network access patterns
            MaliciousPattern {
                pattern_id: "NET_001".to_string(),
                pattern_name: "Network access".to_string(),
                description: "Detects network access capabilities".to_string(),
                category: PatternCategory::NetworkAccess,
                severity: PatternSeverity::Low,
                indicators: vec![],
                regex_patterns: vec![
                    r"(?i)(urllib|requests|http|socket)".to_string(),
                    r"XMLHttpRequest|fetch\(".to_string(),
                    r"curl|wget".to_string(),
                ],
                file_patterns: vec![],
                evidence: vec![],
            },
            // File system access patterns
            MaliciousPattern {
                pattern_id: "FILE_001".to_string(),
                pattern_name: "File system manipulation".to_string(),
                description: "Detects suspicious file system operations".to_string(),
                category: PatternCategory::FileSystemAccess,
                severity: PatternSeverity::Medium,
                indicators: vec![],
                regex_patterns: vec![
                    r"(?i)\b(unlink|rmdir|chmod|chown)\b".to_string(),
                    r"fs\.unlink|fs\.rmdir".to_string(),
                    r"rm\s+-rf|del\s+/[qsf]".to_string(),
                ],
                file_patterns: vec![],
                evidence: vec![],
            },
        ]
    }
}

/// Pattern database for managing pattern definitions
pub struct PatternDatabase {
    patterns: BTreeMap<String, MaliciousPattern>,
    categories: BTreeMap<PatternCategory, Vec<String>>,
}

impl PatternDatabase {
    /// Create a new pattern database
    pub fn new() -> Result<Self> {
        let mut db = Self {
            patterns: BTreeMap::new(),
            categories: BTreeMap::new(),
        };

        db.replace_patterns(PatternMatcher::default_patterns())?;
        Ok(db)
    }

    /// Add a pattern to the database
    pub fn add_pattern(&mut self, pattern: MaliciousPattern) -> Result<()> {
        let mut merged = self.patterns.clone();
        merged.insert(pattern.pattern_id.clone(), pattern);
        let patterns = merged.into_values().collect::<Vec<_>>();
        PatternMatcher::validate_collection(&patterns)?;
        self.replace_patterns(patterns)
    }

    fn insert_validated(&mut self, pattern: MaliciousPattern) {
        let id = pattern.pattern_id.clone();
        let category = pattern.category;

        if let Some(previous) = self.patterns.insert(id.clone(), pattern) {
            let remove_category = if let Some(ids) = self.categories.get_mut(&previous.category) {
                ids.retain(|existing| existing != &id);
                ids.is_empty()
            } else {
                false
            };
            if remove_category {
                self.categories.remove(&previous.category);
            }
        }
        let ids = self.categories.entry(category).or_default();
        if !ids.contains(&id) {
            ids.push(id);
            ids.sort_unstable();
        }
    }

    fn replace_patterns(&mut self, patterns: Vec<MaliciousPattern>) -> Result<()> {
        PatternMatcher::validate_collection(&patterns)?;
        let mut replacement = Self {
            patterns: BTreeMap::new(),
            categories: BTreeMap::new(),
        };
        for pattern in patterns {
            replacement.insert_validated(pattern);
        }
        *self = replacement;
        Ok(())
    }

    /// Get pattern by ID
    pub fn get_pattern(&self, id: &str) -> Option<&MaliciousPattern> {
        self.patterns.get(id)
    }

    /// Get patterns by category
    pub fn get_by_category(&self, category: &PatternCategory) -> Vec<&MaliciousPattern> {
        self.categories
            .get(category)
            .map(|ids| ids.iter().filter_map(|id| self.patterns.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get all patterns
    pub fn all_patterns(&self) -> Vec<&MaliciousPattern> {
        self.patterns.values().collect()
    }

    /// Export patterns to JSON
    pub fn export_json(&self) -> Result<String> {
        let patterns: Vec<_> = self.patterns.values().cloned().collect();
        Ok(serde_json::to_string_pretty(&patterns)?)
    }

    /// Import patterns from JSON
    pub fn import_json(&mut self, json: &str) -> Result<usize> {
        if json.len() > crate::limits::MAX_PATTERN_INPUT_BYTES {
            bail!("pattern JSON exceeds the configured input limit");
        }
        let patterns: Vec<MaliciousPattern> = serde_json::from_str(json)?;
        PatternMatcher::validate_collection(&patterns)?;
        let count = patterns.len();
        let mut merged = self.patterns.clone();
        for pattern in patterns {
            merged.insert(pattern.pattern_id.clone(), pattern);
        }
        self.replace_patterns(merged.into_values().collect())?;
        Ok(count)
    }
}

fn compile_regex(pattern: &str) -> Result<Regex, regex::Error> {
    RegexBuilder::new(pattern)
        .size_limit(crate::limits::MAX_REGEX_COMPILED_BYTES)
        .dfa_size_limit(crate::limits::MAX_REGEX_COMPILED_BYTES)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(id: &str, category: PatternCategory, regexes: Vec<String>) -> MaliciousPattern {
        MaliciousPattern {
            pattern_id: id.to_string(),
            pattern_name: id.to_string(),
            description: "test pattern".to_string(),
            category,
            severity: PatternSeverity::Low,
            indicators: vec![],
            regex_patterns: regexes,
            file_patterns: vec![],
            evidence: vec![],
        }
    }

    #[test]
    fn scan_is_fallible_and_bounded() {
        let matcher = PatternMatcher::with_patterns(vec![pattern(
            "one",
            PatternCategory::NetworkAccess,
            vec!["needle".to_string()],
        )])
        .expect("valid matcher");
        let matches = matcher.scan("needle", None).expect("bounded scan");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].evidence.len(), 1);
        assert!(
            matcher
                .scan(
                    &"x".repeat(crate::limits::MAX_PATTERN_INPUT_BYTES + 1),
                    None
                )
                .is_err()
        );
    }

    #[test]
    fn definition_evidence_is_rejected_before_storage() {
        let mut invalid = pattern(
            "evidence",
            PatternCategory::NetworkAccess,
            vec!["needle".to_string()],
        );
        invalid.evidence = vec!["caller-supplied evidence".to_string()];
        assert!(PatternMatcher::with_patterns(vec![invalid.clone()]).is_err());

        let mut database = PatternDatabase::new().expect("default database");
        assert!(database.add_pattern(invalid).is_err());
    }

    #[test]
    fn literal_indicators_match_case_sensitively_and_empty_matchers_are_rejected() {
        let mut literal = pattern("literal", PatternCategory::NetworkAccess, vec![]);
        literal.indicators = vec!["Exact.Signal".to_string()];
        let matcher = PatternMatcher::with_patterns(vec![literal]).expect("valid matcher");
        assert!(matcher.scan("exact.signal", None).expect("scan").is_empty());
        let matches = matcher.scan("prefix Exact.Signal", None).expect("scan");
        assert_eq!(matches.len(), 1);
        assert!(matches[0].evidence[0].contains("byte offset 7"));

        for mut invalid in [
            pattern("indicator", PatternCategory::NetworkAccess, vec![]),
            pattern("file", PatternCategory::NetworkAccess, vec![]),
            pattern("regex", PatternCategory::NetworkAccess, vec![String::new()]),
        ] {
            if invalid.pattern_id == "indicator" {
                invalid.indicators.push(String::new());
            } else if invalid.pattern_id == "file" {
                invalid.file_patterns.push(String::new());
            }
            assert!(PatternMatcher::with_patterns(vec![invalid]).is_err());
        }
    }

    #[test]
    fn default_patterns_do_not_match_benign_identifier_substrings() {
        let matcher = PatternMatcher::new().expect("default matcher");
        assert!(
            matcher
                .scan(
                    "node prevalence.js && node validation.js && sync -e && node startup.js",
                    Some("package.json#scripts")
                )
                .expect("scan")
                .is_empty()
        );

        let socket_matches = matcher
            .scan("client = socket.socket()", Some("setup.py"))
            .expect("scan");
        assert!(
            socket_matches
                .iter()
                .all(|pattern| pattern.pattern_id != "BACK_001")
        );
        assert!(
            socket_matches
                .iter()
                .any(|pattern| pattern.pattern_id == "NET_001")
        );
    }

    #[test]
    fn aggregate_regex_count_and_bytes_are_rejected_before_compilation() {
        let count_patterns = (0..=crate::limits::MAX_TOTAL_REGEXES
            / crate::limits::MAX_REGEXES_PER_PATTERN)
            .map(|index| {
                pattern(
                    &format!("count-{index}"),
                    PatternCategory::NetworkAccess,
                    vec!["a".to_string(); crate::limits::MAX_REGEXES_PER_PATTERN],
                )
            })
            .collect();
        assert!(PatternMatcher::with_patterns(count_patterns).is_err());

        let bytes_per_regex = crate::limits::MAX_REGEX_BYTES;
        let regex_count = crate::limits::MAX_TOTAL_REGEX_BYTES / bytes_per_regex + 1;
        let byte_patterns = (0..regex_count)
            .map(|index| {
                pattern(
                    &format!("bytes-{index}"),
                    PatternCategory::NetworkAccess,
                    vec!["a".repeat(bytes_per_regex)],
                )
            })
            .collect();
        assert!(PatternMatcher::with_patterns(byte_patterns).is_err());
    }

    #[test]
    fn database_updates_category_without_duplicates_and_exports_stably() {
        let mut database = PatternDatabase::new().expect("default database");
        database
            .add_pattern(pattern(
                "custom",
                PatternCategory::NetworkAccess,
                vec!["a".to_string()],
            ))
            .expect("add pattern");
        database
            .add_pattern(pattern(
                "custom",
                PatternCategory::CodeExecution,
                vec!["b".to_string()],
            ))
            .expect("replace pattern");

        assert!(
            database
                .get_by_category(&PatternCategory::NetworkAccess)
                .iter()
                .all(|pattern| pattern.pattern_id != "custom")
        );
        assert_eq!(
            database
                .get_by_category(&PatternCategory::CodeExecution)
                .iter()
                .filter(|pattern| pattern.pattern_id == "custom")
                .count(),
            1
        );
        assert_eq!(
            database.export_json().expect("export"),
            database.export_json().expect("repeat export")
        );
    }

    #[test]
    fn invalid_import_is_atomic() {
        let mut database = PatternDatabase::new().expect("default database");
        let before = database.export_json().expect("export before");
        let invalid = serde_json::to_string(&vec![pattern(
            "invalid",
            PatternCategory::CodeExecution,
            vec!["(".to_string()],
        )])
        .expect("serialize invalid definition");

        assert!(database.import_json(&invalid).is_err());
        assert_eq!(database.export_json().expect("export after"), before);

        let duplicate = serde_json::to_string(&vec![
            pattern(
                "duplicate",
                PatternCategory::CodeExecution,
                vec!["a".to_string()],
            ),
            pattern(
                "duplicate",
                PatternCategory::NetworkAccess,
                vec!["b".to_string()],
            ),
        ])
        .expect("serialize duplicate definitions");
        assert!(database.import_json(&duplicate).is_err());
        assert_eq!(
            database.export_json().expect("export after duplicate"),
            before
        );
    }
}
