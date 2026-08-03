//! Compile and run an application-owned pattern set.

use threatflux_package_security::core::patterns::{PatternCategory, PatternSeverity};
use threatflux_package_security::core::{MaliciousPattern, PatternMatcher};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matcher = PatternMatcher::with_patterns(vec![MaliciousPattern {
        pattern_id: "ORG_001".to_string(),
        pattern_name: "Unapproved install endpoint".to_string(),
        description: "Flags an organization-specific endpoint".to_string(),
        category: PatternCategory::NetworkAccess,
        severity: PatternSeverity::High,
        indicators: vec!["packages.example.invalid".to_string()],
        regex_patterns: vec![r"https://packages\.example\.invalid/".to_string()],
        file_patterns: vec![],
        evidence: vec![],
    }])?;

    let content = "curl https://packages.example.invalid/bootstrap.sh";
    for finding in matcher.scan(content, Some("package.json"))? {
        println!(
            "{} [{:?}]: {:?}",
            finding.pattern_id.escape_default(),
            finding.severity,
            finding.evidence
        );
    }

    Ok(())
}
