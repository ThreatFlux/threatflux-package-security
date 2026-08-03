//! Risk assessment and scoring framework

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

use super::{MaliciousPattern, Vulnerability};

/// Risk level categories
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    /// Convert from numeric risk score
    pub fn from_score(score: f32) -> Self {
        if !score.is_finite() {
            return Self::Critical;
        }
        match score {
            s if s >= 80.0 => Self::Critical,
            s if s >= 60.0 => Self::High,
            s if s >= 40.0 => Self::Medium,
            s if s >= 20.0 => Self::Low,
            _ => Self::Informational,
        }
    }

    /// Get color representation for UI
    pub fn color(&self) -> &'static str {
        match self {
            Self::Critical => "#FF0000",      // Red
            Self::High => "#FF6600",          // Orange
            Self::Medium => "#FFCC00",        // Yellow
            Self::Low => "#99CC00",           // Light Green
            Self::Informational => "#4B5563", // Gray
        }
    }
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Informational => write!(f, "Informational"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

/// Risk score with detailed breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub total_score: f32,
    pub risk_level: RiskLevel,
    pub components: BTreeMap<String, f32>,
    pub factors: Vec<RiskFactor>,
}

/// Individual risk factor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub category: RiskCategory,
    pub description: String,
    pub severity: RiskLevel,
    pub score_contribution: f32,
    pub evidence: Vec<String>,
    pub mitigation: Option<String>,
}

/// Analyzer-provided supply-chain signal with evidence specific to the
/// capability that was actually inspected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyChainSignal {
    pub score: f32,
    pub description: String,
    pub evidence: Vec<String>,
    pub mitigation: Option<String>,
}

/// Risk categories
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RiskCategory {
    Vulnerability,
    MaliciousCode,
    Typosquatting,
    SupplyChain,
    Maintenance,
    License,
    Privacy,
    Quality,
}

/// Complete risk assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub risk_score: RiskScore,
    pub summary: String,
    pub detailed_findings: Vec<Finding>,
    pub recommendations: Vec<Recommendation>,
    pub security_posture: SecurityPosture,
}

/// Security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub finding_type: FindingType,
    pub severity: RiskLevel,
    pub title: String,
    pub description: String,
    pub evidence: Vec<String>,
    pub affected_components: Vec<String>,
}

/// Finding types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FindingType {
    Vulnerability,
    MaliciousPattern,
    SuspiciousActivity,
    PolicyViolation,
    QualityIssue,
}

/// Recommendation for addressing risks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub priority: Priority,
    pub action: String,
    pub reason: String,
    pub effort: EffortLevel,
    pub impact: ImpactLevel,
}

/// Priority levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Low,
    Medium,
    High,
    Critical,
}

/// Effort required for remediation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EffortLevel {
    Trivial,
    Low,
    Medium,
    High,
    VeryHigh,
}

/// Impact of remediation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ImpactLevel {
    None,
    Low,
    Medium,
    High,
}

/// Overall security posture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPosture {
    /// Whether this analysis produced advisory matches. `false` does not claim
    /// comprehensive absence; consult the result's database metadata.
    pub vulnerability_matches_present: bool,
    pub high_severity_pattern_matches_present: bool,
    pub supply_chain_risks: bool,
    pub actively_maintained: Option<bool>,
    pub trusted_publisher: Option<bool>,
    pub security_practices_score: Option<f32>,
}

/// Risk calculator
pub struct RiskCalculator {
    weights: BTreeMap<RiskCategory, f32>,
}

impl RiskCalculator {
    /// Create a new risk calculator with default weights
    pub fn new() -> Self {
        let mut weights = BTreeMap::new();
        weights.insert(RiskCategory::Vulnerability, 1.0);
        weights.insert(RiskCategory::MaliciousCode, 1.0);
        weights.insert(RiskCategory::Typosquatting, 1.0);
        weights.insert(RiskCategory::SupplyChain, 1.0);
        weights.insert(RiskCategory::Maintenance, 0.5);
        weights.insert(RiskCategory::License, 0.3);
        weights.insert(RiskCategory::Privacy, 0.8);
        weights.insert(RiskCategory::Quality, 0.4);

        Self { weights }
    }

    /// Calculate risk score from various inputs
    pub fn calculate(
        &self,
        vulnerabilities: &[Vulnerability],
        malicious_patterns: &[MaliciousPattern],
        is_typosquatting: bool,
        supply_chain_signal: Option<SupplyChainSignal>,
        maintenance_score: f32,
    ) -> Result<RiskScore> {
        let supply_chain_score = supply_chain_signal
            .as_ref()
            .map_or(0.0, |signal| signal.score);
        validate_score("supply-chain", supply_chain_score)?;
        validate_score("maintenance", maintenance_score)?;
        if let Some(signal) = &supply_chain_signal
            && (signal.description.is_empty()
                || signal.description.len() > crate::limits::MAX_PATTERN_DESCRIPTION_BYTES
                || signal.evidence.len() > crate::limits::MAX_TOTAL_EVIDENCE
                || signal.evidence.iter().any(|evidence| {
                    evidence.is_empty() || evidence.len() > crate::limits::MAX_METADATA_FIELD_BYTES
                })
                || signal
                    .mitigation
                    .as_ref()
                    .is_some_and(|value| value.len() > crate::limits::MAX_METADATA_FIELD_BYTES))
        {
            bail!("supply-chain signal exceeds the configured limits");
        }
        let mut components = BTreeMap::new();
        let mut factors = Vec::new();

        // Vulnerability score
        let vuln_score = self.calculate_vulnerability_score(vulnerabilities);
        if !vulnerabilities.is_empty() {
            components.insert("vulnerabilities".to_string(), vuln_score);
            factors.push(RiskFactor {
                category: RiskCategory::Vulnerability,
                description: format!("{} advisory matches", vulnerabilities.len()),
                severity: RiskLevel::from_score(vuln_score),
                score_contribution: vuln_score * self.weights[&RiskCategory::Vulnerability],
                evidence: vulnerabilities
                    .iter()
                    .take(crate::limits::MAX_TOTAL_EVIDENCE)
                    .map(|v| {
                        format!(
                            "{}: {}",
                            v.advisory_id.escape_default(),
                            v.title.escape_default()
                        )
                    })
                    .collect(),
                mitigation: Some(
                    if vulnerabilities.iter().any(|vulnerability| {
                        vulnerability.patch_available && !vulnerability.fixed_versions.is_empty()
                    }) {
                        "Review each advisory and upgrade to an applicable reviewed fixed version"
                    } else {
                        "Review each advisory and apply source-recommended mitigations"
                    }
                    .to_string(),
                ),
            });
        }

        // Heuristic pattern score
        let malicious_score = self.calculate_malicious_score(malicious_patterns);
        if malicious_score > 0.0 {
            components.insert("malicious_code".to_string(), malicious_score);
            factors.push(RiskFactor {
                category: RiskCategory::MaliciousCode,
                description: format!("{} heuristic pattern matches", malicious_patterns.len()),
                severity: RiskLevel::from_score(malicious_score),
                score_contribution: malicious_score * self.weights[&RiskCategory::MaliciousCode],
                evidence: malicious_patterns
                    .iter()
                    .map(|p| p.pattern_name.escape_default().to_string())
                    .collect(),
                mitigation: Some(
                    "Review the matched evidence and package source before deciding whether to use it"
                        .to_string(),
                ),
            });
        }

        // Typosquatting
        if is_typosquatting {
            let typo_score = 25.0;
            components.insert("typosquatting".to_string(), typo_score);
            factors.push(RiskFactor {
                category: RiskCategory::Typosquatting,
                description: "Package name is suspiciously similar to popular package".to_string(),
                severity: RiskLevel::Low,
                score_contribution: typo_score * self.weights[&RiskCategory::Typosquatting],
                evidence: vec!["Name similarity detected".to_string()],
                mitigation: Some("Verify correct package name".to_string()),
            });
        }

        // Supply chain
        if let Some(signal) = supply_chain_signal {
            components.insert("supply_chain".to_string(), supply_chain_score);
            factors.push(RiskFactor {
                category: RiskCategory::SupplyChain,
                description: signal.description,
                severity: RiskLevel::from_score(supply_chain_score),
                score_contribution: supply_chain_score * self.weights[&RiskCategory::SupplyChain],
                evidence: signal.evidence,
                mitigation: signal.mitigation,
            });
        }

        // A score of 50 means maintenance is unknown/neutral. Only a lower
        // application-provided score contributes risk.
        if maintenance_score < 50.0 {
            let maintenance_risk = 50.0 - maintenance_score;
            components.insert("maintenance".to_string(), maintenance_risk);
            factors.push(RiskFactor {
                category: RiskCategory::Maintenance,
                description: "Low maintenance-confidence score".to_string(),
                severity: RiskLevel::from_score(maintenance_risk),
                score_contribution: maintenance_risk * self.weights[&RiskCategory::Maintenance],
                evidence: vec![format!(
                    "Maintenance confidence: {maintenance_score:.1}/100"
                )],
                mitigation: Some("Review release and maintainer activity".to_string()),
            });
        }

        // Calculate total
        let total_score: f32 = components
            .iter()
            .map(|(component, score)| {
                let weight = match component.as_str() {
                    "vulnerabilities" => self.weights[&RiskCategory::Vulnerability],
                    "malicious_code" => self.weights[&RiskCategory::MaliciousCode],
                    "typosquatting" => self.weights[&RiskCategory::Typosquatting],
                    "supply_chain" => self.weights[&RiskCategory::SupplyChain],
                    "maintenance" => self.weights[&RiskCategory::Maintenance],
                    _ => 1.0,
                };
                score * weight
            })
            .sum::<f32>()
            .min(100.0);

        Ok(RiskScore {
            total_score,
            risk_level: RiskLevel::from_score(total_score),
            components,
            factors,
        })
    }

    fn calculate_vulnerability_score(&self, vulnerabilities: &[Vulnerability]) -> f32 {
        let highest = vulnerabilities
            .iter()
            .map(|vulnerability| match vulnerability.severity {
                super::VulnerabilitySeverity::None => 0.0,
                super::VulnerabilitySeverity::Low => 20.0,
                super::VulnerabilitySeverity::Medium => 40.0,
                super::VulnerabilitySeverity::High => 60.0,
                super::VulnerabilitySeverity::Critical => 85.0,
            })
            .fold(0.0_f32, f32::max);
        let additional = vulnerabilities.len().saturating_sub(1) as f32 * 5.0;
        (highest + additional).min(100.0)
    }

    fn calculate_malicious_score(&self, patterns: &[MaliciousPattern]) -> f32 {
        patterns
            .iter()
            .map(|pattern| match pattern.severity {
                super::patterns::PatternSeverity::Low => 5.0,
                super::patterns::PatternSeverity::Medium => 15.0,
                super::patterns::PatternSeverity::High => 40.0,
                super::patterns::PatternSeverity::Critical => 75.0,
            })
            .sum::<f32>()
            .min(95.0)
    }
}

fn validate_score(name: &str, score: f32) -> Result<()> {
    if !score.is_finite() || !(0.0..=100.0).contains(&score) {
        bail!("{name} score must be finite and between 0 and 100");
    }
    Ok(())
}

impl Default for RiskCalculator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::patterns::{PatternCategory, PatternSeverity};

    fn pattern(severity: PatternSeverity) -> MaliciousPattern {
        MaliciousPattern {
            pattern_id: "test".to_string(),
            pattern_name: "test".to_string(),
            description: "test".to_string(),
            category: PatternCategory::NetworkAccess,
            severity,
            indicators: vec![],
            regex_patterns: vec![],
            file_patterns: vec![],
            evidence: vec![],
        }
    }

    fn supply_chain_signal(score: f32) -> SupplyChainSignal {
        SupplyChainSignal {
            score,
            description: "Test supply-chain signal".to_string(),
            evidence: vec!["test evidence".to_string()],
            mitigation: None,
        }
    }

    #[test]
    fn low_severity_capability_is_not_promoted_to_critical() {
        let score = RiskCalculator::new()
            .calculate(&[], &[pattern(PatternSeverity::Low)], false, None, 100.0)
            .expect("valid score");
        assert_eq!(score.total_score, 5.0);
        assert_eq!(score.risk_level, RiskLevel::Informational);
        assert_eq!(score.factors[0].severity, RiskLevel::Informational);
    }

    #[test]
    fn component_weighting_is_deterministic_and_bounded() {
        let score = RiskCalculator::new()
            .calculate(
                &[],
                &[pattern(PatternSeverity::Critical)],
                true,
                Some(supply_chain_signal(50.0)),
                100.0,
            )
            .expect("valid score");
        assert_eq!(score.total_score, 100.0);
        assert_eq!(
            score.components.keys().cloned().collect::<Vec<_>>(),
            vec!["malicious_code", "supply_chain", "typosquatting"]
        );
    }

    #[test]
    fn critical_advisory_is_critical_and_similarity_alone_is_low() {
        let vulnerability = Vulnerability {
            package_name: "test".to_string(),
            package_type: "test".to_string(),
            advisory_id: "TEST-1".to_string(),
            cve_id: None,
            title: "test".to_string(),
            description: "test".to_string(),
            severity: super::super::VulnerabilitySeverity::Critical,
            cvss_score: None,
            cvss_vector: None,
            cvss_source: None,
            affected_versions: vec![],
            fixed_versions: vec![],
            published_date: None,
            updated_date: None,
            references: vec![],
            cwe_ids: vec![],
            exploit_available: None,
            patch_available: false,
        };
        let critical = RiskCalculator::new()
            .calculate(&[vulnerability], &[], false, None, 50.0)
            .expect("valid score");
        assert_eq!(critical.risk_level, RiskLevel::Critical);

        let typo = RiskCalculator::new()
            .calculate(&[], &[], true, None, 50.0)
            .expect("valid score");
        assert_eq!(typo.total_score, 25.0);
        assert_eq!(typo.risk_level, RiskLevel::Low);
    }

    #[test]
    fn rejects_non_finite_or_out_of_range_scores() {
        let calculator = RiskCalculator::new();
        assert!(
            calculator
                .calculate(&[], &[], false, Some(supply_chain_signal(f32::NAN)), 50.0,)
                .is_err()
        );
        assert!(calculator.calculate(&[], &[], false, None, 101.0).is_err());
        assert_eq!(RiskLevel::from_score(f32::NAN), RiskLevel::Critical);
    }
}
