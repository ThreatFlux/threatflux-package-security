//! Core package traits and structures

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use super::{DependencyAnalysis, MaliciousPattern, RiskAssessment, Vulnerability};

/// Basic package information common to all package types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMetadata {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub author: Option<String>,
    pub license: Option<String>,
    pub homepage: Option<String>,
    pub repository: Option<String>,
    pub keywords: Vec<String>,
    pub publish_date: Option<String>,
}

/// Package quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityMetrics {
    pub documentation_score: f32,
    pub has_tests: bool,
    pub has_ci_cd: bool,
    pub maintenance_score: f32,
}

impl Default for QualityMetrics {
    fn default() -> Self {
        Self {
            documentation_score: 0.5,
            has_tests: false,
            has_ci_cd: false,
            maintenance_score: 0.5,
        }
    }
}

impl QualityMetrics {
    pub fn documentation_score(&self) -> f32 {
        self.documentation_score
    }

    pub fn has_tests(&self) -> bool {
        self.has_tests
    }

    pub fn has_ci_cd(&self) -> bool {
        self.has_ci_cd
    }
}

/// Typosquatting risk assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TyposquattingRisk {
    pub is_potential_typosquatting: bool,
    pub similar_packages: Vec<String>,
    pub confidence_score: f32,
}

impl TyposquattingRisk {
    pub fn is_potential_typosquatting(&self) -> bool {
        self.is_potential_typosquatting
    }

    pub fn similar_packages(&self) -> &[String] {
        &self.similar_packages
    }
}

/// Package-specific information trait
pub trait PackageInfo: Send + Sync {
    /// Get basic metadata
    fn metadata(&self) -> &PackageMetadata;

    /// Get package type identifier
    fn package_type(&self) -> &str;

    /// Get custom attributes specific to this package type
    fn custom_attributes(&self) -> HashMap<String, serde_json::Value>;

    /// Get package name (convenience method)
    fn name(&self) -> &str {
        &self.metadata().name
    }
}

/// Analysis result trait
pub trait AnalysisResult: Send + Sync {
    /// Get the package info
    fn package_info(&self) -> &dyn PackageInfo;

    /// Get risk assessment
    fn risk_assessment(&self) -> &RiskAssessment;

    /// Get dependency analysis
    fn dependency_analysis(&self) -> &DependencyAnalysis;

    /// Get detected vulnerabilities
    fn vulnerabilities(&self) -> &[Vulnerability];

    /// Get detected malicious patterns
    fn malicious_patterns(&self) -> &[MaliciousPattern];

    /// Convert to JSON representation
    fn to_json(&self) -> Result<serde_json::Value>;

    /// Get overall risk level (convenience method)
    fn overall_risk_level(&self) -> super::RiskLevel {
        self.risk_assessment().risk_score.risk_level
    }

    /// Get malicious indicators (convenience method)
    fn malicious_indicators(&self) -> &[super::MaliciousPattern] {
        self.malicious_patterns()
    }

    /// Get supply chain risk score (convenience method)
    fn supply_chain_risk_score(&self) -> f32 {
        self.risk_assessment()
            .risk_score
            .components
            .get("supply_chain")
            .copied()
            .unwrap_or(0.0)
    }

    /// Get quality metrics (placeholder)
    fn quality_metrics(&self) -> super::QualityMetrics {
        super::QualityMetrics::default()
    }

    /// Get typosquatting risk (default implementation)
    fn typosquatting_risk(&self) -> Option<TyposquattingRisk> {
        None
    }
}

/// Package analyzer trait
#[async_trait]
pub trait PackageAnalyzer: Send + Sync {
    /// The specific package type this analyzer handles
    type Package: PackageInfo;

    /// The analysis result type
    type Analysis: AnalysisResult;

    /// Analyze a package from the given path
    async fn analyze(&self, path: &Path) -> Result<Self::Analysis>;

    /// Check if this analyzer can handle the given path
    fn can_analyze(&self, path: &Path) -> bool;

    /// Get analyzer name
    fn name(&self) -> &str;

    /// Get supported file extensions
    fn supported_extensions(&self) -> Vec<&str>;
}

/// Common package analysis options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisOptions {
    /// Enable deep dependency analysis
    pub analyze_dependencies: bool,

    /// Check against vulnerability databases
    pub check_vulnerabilities: bool,

    /// Scan for malicious patterns
    pub scan_malicious_patterns: bool,

    /// Enable typosquatting detection
    pub detect_typosquatting: bool,

    /// Maximum dependency depth to analyze
    pub max_dependency_depth: usize,

    /// Timeout for analysis in seconds
    pub timeout_seconds: u64,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            analyze_dependencies: true,
            check_vulnerabilities: true,
            scan_malicious_patterns: true,
            detect_typosquatting: true,
            max_dependency_depth: 5,
            timeout_seconds: 300,
        }
    }
}
