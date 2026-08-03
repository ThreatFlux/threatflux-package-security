//! Dependency analysis structures

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::Vulnerability;

/// Dependency information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    pub version_spec: String,
    pub resolved_version: Option<String>,
    pub dependency_type: DependencyType,
    /// Whether this dependency is known to be declared directly by the
    /// analyzed package. `None` means the source format does not establish
    /// directness (for example, a standalone `requirements.txt`).
    pub is_direct: Option<bool>,
    /// Whether this dependency is known to be development-only. `None` means
    /// the source format does not provide that classification.
    pub is_dev: Option<bool>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub license: Option<String>,
    pub dependencies: Vec<Dependency>, // Transitive dependencies
}

/// Type of dependency
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DependencyType {
    /// The declaration source does not establish a dependency role.
    Unknown,
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
    /// Requirements that were syntactically valid input but could not be
    /// resolved to an exact package/version pair by the offline parser.
    pub unresolved_requirements: Vec<String>,
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
    pub license_types: BTreeMap<String, usize>,
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
                license_types: BTreeMap::new(),
                has_copyleft: false,
                has_proprietary: false,
                unknown_licenses: Vec::new(),
                license_conflicts: Vec::new(),
            },
            outdated_dependencies: Vec::new(),
            unresolved_requirements: Vec::new(),
        }
    }
}

impl DependencyAnalysis {
    /// Return one deterministic record per ecosystem/package/advisory identity.
    pub(crate) fn unique_vulnerabilities(&self) -> Vec<Vulnerability> {
        deduplicate_vulnerabilities(
            self.dependency_tree
                .iter()
                .flat_map(|dependency| dependency.vulnerabilities.iter().cloned()),
        )
    }

    /// Rebuild the dependency summary without counting duplicate advisory records.
    pub(crate) fn rebuild_vulnerability_summary(&mut self) {
        let vulnerabilities = self.unique_vulnerabilities();
        let mut summary = VulnerabilitySummary {
            total_vulnerabilities: vulnerabilities.len(),
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            vulnerable_dependencies: Vec::new(),
        };

        for vulnerability in vulnerabilities {
            match vulnerability.severity {
                super::VulnerabilitySeverity::Critical => summary.critical_count += 1,
                super::VulnerabilitySeverity::High => summary.high_count += 1,
                super::VulnerabilitySeverity::Medium => summary.medium_count += 1,
                super::VulnerabilitySeverity::Low => summary.low_count += 1,
                super::VulnerabilitySeverity::None => {}
            }
            let dependency = vulnerability.package_name;
            if !summary.vulnerable_dependencies.contains(&dependency) {
                summary.vulnerable_dependencies.push(dependency);
            }
        }
        self.vulnerability_summary = summary;
    }
}

/// Return one deterministic record per ecosystem/package/advisory identity.
pub(crate) fn deduplicate_vulnerabilities(
    vulnerabilities: impl IntoIterator<Item = Vulnerability>,
) -> Vec<Vulnerability> {
    let mut unique = BTreeMap::new();
    for vulnerability in vulnerabilities {
        unique
            .entry((
                vulnerability.package_type.clone(),
                vulnerability.package_name.clone(),
                vulnerability.advisory_id.clone(),
            ))
            .or_insert(vulnerability);
    }
    unique.into_values().collect()
}
