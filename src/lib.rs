//! ThreatFlux Package Security Library
//!
//! Bounded metadata inspection and review signals for npm and Python project
//! directories plus ZIP-compatible Java package archives.

pub mod analyzers;
pub mod core;
pub mod limits;
pub mod utils;
pub mod vulnerability_db;

pub use core::{
    AnalysisResult, MaliciousPattern, PackageAnalyzer, PackageInfo, RiskLevel, RiskScore,
    TyposquattingRisk, Vulnerability, VulnerabilitySeverity,
};

pub use analyzers::{java::JavaAnalyzer, npm::NpmAnalyzer, python::PythonAnalyzer};

pub use core::AdvisoryCatalog;
pub use vulnerability_db::VulnerabilityDatabase;

use anyhow::Result;
use std::path::Path;

/// Main entry point for package security analysis
pub struct PackageSecurityAnalyzer {
    npm_analyzer: NpmAnalyzer,
    python_analyzer: PythonAnalyzer,
    java_analyzer: JavaAnalyzer,
}

impl PackageSecurityAnalyzer {
    /// Create a new package security analyzer with default settings
    pub fn new() -> Result<Self> {
        Ok(Self {
            npm_analyzer: NpmAnalyzer::new()?,
            python_analyzer: PythonAnalyzer::new()?,
            java_analyzer: JavaAnalyzer::new()?,
        })
    }

    /// Create a unified analyzer from application-configured ecosystem analyzers.
    pub fn from_analyzers(
        npm_analyzer: NpmAnalyzer,
        python_analyzer: PythonAnalyzer,
        java_analyzer: JavaAnalyzer,
    ) -> Self {
        Self {
            npm_analyzer,
            python_analyzer,
            java_analyzer,
        }
    }

    /// Create a unified analyzer with application-provided npm and Python
    /// vulnerability databases.
    pub fn with_vulnerability_databases(
        npm_database: Box<dyn VulnerabilityDatabase>,
        python_database: Box<dyn VulnerabilityDatabase>,
    ) -> Result<Self> {
        Ok(Self {
            npm_analyzer: NpmAnalyzer::with_database(npm_database)?,
            python_analyzer: PythonAnalyzer::with_database(python_database)?,
            java_analyzer: JavaAnalyzer::new()?,
        })
    }

    /// Analyze a package file or directory.
    ///
    /// Call this from an active Tokio runtime. If the returned future is
    /// polled without one, analysis returns an error.
    pub async fn analyze(&self, path: impl AsRef<Path>) -> Result<Box<dyn AnalysisResult>> {
        crate::utils::require_tokio_runtime()?;
        let path = path.as_ref();

        let npm = self.is_npm_package(path);
        let python = self.is_python_package(path);
        let java = self.is_java_package(path);
        match (npm, python, java) {
            (true, false, false) => Ok(Box::new(self.npm_analyzer.analyze(path).await?)),
            (false, true, false) => Ok(Box::new(self.python_analyzer.analyze(path).await?)),
            (false, false, true) => Ok(Box::new(self.java_analyzer.analyze(path).await?)),
            (false, false, false) => anyhow::bail!("Unknown package type for path: {path:?}"),
            _ => anyhow::bail!(
                "Ambiguous package input at {path:?}; choose an ecosystem analyzer explicitly"
            ),
        }
    }

    /// Check if path is an npm package
    fn is_npm_package(&self, path: &Path) -> bool {
        crate::utils::input::has_regular_project_file(path, Path::new("package.json"))
    }

    /// Check if path is a Python package
    fn is_python_package(&self, path: &Path) -> bool {
        ["pyproject.toml", "setup.cfg", "setup.py"]
            .iter()
            .any(|file| crate::utils::input::has_regular_project_file(path, Path::new(file)))
    }

    /// Check if path is a Java package
    fn is_java_package(&self, path: &Path) -> bool {
        if let Some(ext) = path.extension() {
            matches!(
                ext.to_str().map(str::to_ascii_lowercase).as_deref(),
                Some("jar") | Some("war") | Some("ear") | Some("apk") | Some("aar")
            )
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_detection() {
        let analyzer = PackageSecurityAnalyzer::new().expect("construct analyzer");
        let npm = tempfile::tempdir().expect("temporary npm project");
        std::fs::write(npm.path().join("package.json"), "{}").expect("write package.json");
        let python = tempfile::tempdir().expect("temporary Python project");
        std::fs::write(python.path().join("pyproject.toml"), "").expect("write pyproject");

        assert!(analyzer.is_npm_package(npm.path()));
        assert!(analyzer.is_python_package(python.path()));
        assert!(!analyzer.is_npm_package(Path::new("package.tgz")));
        assert!(!analyzer.is_python_package(Path::new("package.whl")));
        assert!(analyzer.is_java_package(Path::new("app.JAR")));
    }
}
