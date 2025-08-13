//! Pattern matching utilities

use regex::Regex;
use std::collections::HashMap;

/// Pattern matcher for common security patterns
pub struct PatternMatcher {
    patterns: HashMap<String, Regex>,
}

impl PatternMatcher {
    /// Create a new pattern matcher
    pub fn new() -> Self {
        let mut patterns = HashMap::new();

        // Common security patterns
        patterns.insert("eval".to_string(), Regex::new(r"eval\s*\(").unwrap());
        patterns.insert("exec".to_string(), Regex::new(r"exec\s*\(").unwrap());
        patterns.insert(
            "base64".to_string(),
            Regex::new(r"base64\.(decode|encode|b64decode|b64encode)").unwrap(),
        );
        patterns.insert(
            "subprocess".to_string(),
            Regex::new(r"subprocess\.(call|run|Popen)").unwrap(),
        );
        patterns.insert(
            "network".to_string(),
            Regex::new(r"(socket|requests|urllib|curl|wget)\s*[\.\(]").unwrap(),
        );

        Self { patterns }
    }

    /// Check if content matches any patterns
    pub fn has_pattern(&self, content: &str, pattern: &str) -> bool {
        self.patterns
            .get(pattern)
            .map(|re| re.is_match(content))
            .unwrap_or(false)
    }

    /// Find all matching patterns
    pub fn find_patterns(&self, content: &str) -> Vec<String> {
        self.patterns
            .iter()
            .filter(|(_, re)| re.is_match(content))
            .map(|(name, _)| name.clone())
            .collect()
    }
}

impl Default for PatternMatcher {
    fn default() -> Self {
        Self::new()
    }
}
