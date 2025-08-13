//! Dependency analysis structures

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::Vulnerability;

/// Dependency information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    pub version_spec: String,
    pub resolved_version: Option<String>,
    pub dependency_type: DependencyType,
    pub is_direct: bool,
    pub is_dev: bool,
    pub vulnerabilities: Vec<Vulnerability>,
    pub license: Option<String>,
    pub dependencies: Vec<Dependency>, // Transitive dependencies
}

/// Type of dependency
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DependencyType {
    Runtime,
    Development,
    Optional,
    Peer,
    Build,
    Test,
}

/// Dependency analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyAnalysis {
    pub total_dependencies: usize,
    pub direct_dependencies: usize,
    pub transitive_dependencies: usize,
    pub dependency_tree: Vec<Dependency>,
    pub max_depth: usize,
    pub vulnerability_summary: VulnerabilitySummary,
    pub license_summary: LicenseSummary,
    pub outdated_dependencies: Vec<OutdatedDependency>,
}

/// Vulnerability summary for dependencies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilitySummary {
    pub total_vulnerabilities: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub vulnerable_dependencies: Vec<String>,
}

/// License summary for dependencies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseSummary {
    pub license_types: HashMap<String, usize>,
    pub has_copyleft: bool,
    pub has_proprietary: bool,
    pub unknown_licenses: Vec<String>,
    pub license_conflicts: Vec<LicenseConflict>,
}

/// License conflict information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseConflict {
    pub dependency: String,
    pub license: String,
    pub conflicts_with: Vec<String>,
    pub reason: String,
}

/// Outdated dependency information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutdatedDependency {
    pub name: String,
    pub current_version: String,
    pub latest_version: String,
    pub version_behind: VersionDifference,
    pub update_urgency: UpdateUrgency,
}

/// Version difference information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionDifference {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

/// Update urgency level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UpdateUrgency {
    Critical, // Security vulnerabilities fixed
    High,     // Major bugs fixed
    Medium,   // Normal updates
    Low,      // Minor changes
}

impl Default for DependencyAnalysis {
    fn default() -> Self {
        Self {
            total_dependencies: 0,
            direct_dependencies: 0,
            transitive_dependencies: 0,
            dependency_tree: Vec::new(),
            max_depth: 0,
            vulnerability_summary: VulnerabilitySummary {
                total_vulnerabilities: 0,
                critical_count: 0,
                high_count: 0,
                medium_count: 0,
                low_count: 0,
                vulnerable_dependencies: Vec::new(),
            },
            license_summary: LicenseSummary {
                license_types: HashMap::new(),
                has_copyleft: false,
                has_proprietary: false,
                unknown_licenses: Vec::new(),
                license_conflicts: Vec::new(),
            },
            outdated_dependencies: Vec::new(),
        }
    }
}
