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

/// Package-specific information trait
pub trait PackageInfo: Send + Sync {
    /// Get basic metadata
    fn metadata(&self) -> &PackageMetadata;

    /// Get package type identifier
    fn package_type(&self) -> &str;

    /// Get custom attributes specific to this package type
    fn custom_attributes(&self) -> HashMap<String, serde_json::Value>;
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
