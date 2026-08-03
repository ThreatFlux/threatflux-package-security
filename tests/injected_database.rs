use async_trait::async_trait;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tempfile::TempDir;
use threatflux_package_security::core::{
    DatabaseCoverage, DatabaseMetadata, Vulnerability, VulnerabilitySeverity,
};
use threatflux_package_security::{
    NpmAnalyzer, PackageAnalyzer, PythonAnalyzer, VulnerabilityDatabase,
};

#[derive(Clone, Default)]
struct Observations {
    calls: Arc<Mutex<Vec<(String, String, String)>>>,
    metadata_calls: Arc<AtomicUsize>,
}

struct RecordingDatabase {
    observations: Observations,
    fail_checks: bool,
}

impl RecordingDatabase {
    fn new(fail_checks: bool) -> (Self, Observations) {
        let observations = Observations::default();
        (
            Self {
                observations: observations.clone(),
                fail_checks,
            },
            observations,
        )
    }
}

#[async_trait]
impl VulnerabilityDatabase for RecordingDatabase {
    async fn check_package(
        &self,
        package_name: &str,
        version: &str,
        package_type: &str,
    ) -> anyhow::Result<Vec<Vulnerability>> {
        self.observations.calls.lock().expect("record calls").push((
            package_name.to_string(),
            version.to_string(),
            package_type.to_string(),
        ));
        if self.fail_checks {
            anyhow::bail!("synthetic database failure");
        }
        if package_name != "range-dep" {
            return Ok(vec![]);
        }
        Ok(vec![Vulnerability {
            package_name: package_name.to_string(),
            package_type: package_type.to_string(),
            advisory_id: "APP-1".to_string(),
            cve_id: None,
            title: "Application-defined range match".to_string(),
            description: "Synthetic test record".to_string(),
            severity: VulnerabilitySeverity::Medium,
            cvss_score: None,
            cvss_vector: None,
            cvss_source: None,
            affected_versions: vec![version.to_string()],
            fixed_versions: vec![],
            published_date: None,
            updated_date: None,
            references: vec![],
            cwe_ids: vec![],
            exploit_available: None,
            patch_available: false,
        }])
    }

    fn metadata(&self) -> DatabaseMetadata {
        self.observations
            .metadata_calls
            .fetch_add(1, Ordering::SeqCst);
        DatabaseMetadata {
            name: "recording-test-database".to_string(),
            coverage: DatabaseCoverage::ApplicationProvided,
            as_of: None,
            provenance: vec!["synthetic test".to_string()],
        }
    }
}

fn write_manifest(directory: &TempDir, content: &str) {
    std::fs::write(directory.path().join("package.json"), content).expect("write package.json");
}

#[tokio::test]
async fn injected_database_receives_ranges_then_subject_and_metadata_is_last() {
    let directory = TempDir::new().expect("temporary directory");
    write_manifest(
        &directory,
        r#"{
          "name":"custom-subject",
          "version":"1.0.0",
          "dependencies":{"range-dep":"^1.2.3"}
        }"#,
    );
    let (database, observations) = RecordingDatabase::new(false);
    let result = NpmAnalyzer::with_database(Box::new(database))
        .expect("construct analyzer")
        .analyze(directory.path())
        .await
        .expect("analyze package");

    assert_eq!(result.vulnerabilities.len(), 1);
    assert_eq!(
        result.dependency_analysis.unresolved_requirements,
        vec!["range-dep@^1.2.3"]
    );
    assert_eq!(
        *observations.calls.lock().expect("read calls"),
        vec![
            (
                "range-dep".to_string(),
                "^1.2.3".to_string(),
                "npm".to_string()
            ),
            (
                "custom-subject".to_string(),
                "1.0.0".to_string(),
                "npm".to_string()
            ),
        ]
    );
    assert_eq!(observations.metadata_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn invalid_input_and_database_errors_do_not_produce_metadata() {
    let malformed = TempDir::new().expect("temporary directory");
    write_manifest(
        &malformed,
        r#"{"name":"invalid-test","version":"1.0.0","scripts":{"test":3}}"#,
    );
    let (database, observations) = RecordingDatabase::new(false);
    assert!(
        NpmAnalyzer::with_database(Box::new(database))
            .expect("construct analyzer")
            .analyze(malformed.path())
            .await
            .is_err()
    );
    assert!(observations.calls.lock().expect("read calls").is_empty());
    assert_eq!(observations.metadata_calls.load(Ordering::SeqCst), 0);

    let valid = TempDir::new().expect("temporary directory");
    write_manifest(&valid, r#"{"name":"failure-test","version":"1.0.0"}"#);
    let (database, observations) = RecordingDatabase::new(true);
    assert!(
        NpmAnalyzer::with_database(Box::new(database))
            .expect("construct analyzer")
            .analyze(valid.path())
            .await
            .is_err()
    );
    assert_eq!(observations.calls.lock().expect("read calls").len(), 1);
    assert_eq!(observations.metadata_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn python_injected_database_receives_ranges_but_not_unevaluated_markers() {
    let directory = TempDir::new().expect("temporary directory");
    std::fs::write(
        directory.path().join("pyproject.toml"),
        r#"
[project]
name = "custom-subject"
version = "1.0.0"
dependencies = [
  "range-dep>=1.2",
  "conditional-dep==2.0.0; python_version < '3.12'",
]
"#,
    )
    .expect("write pyproject.toml");
    let (database, observations) = RecordingDatabase::new(false);
    let result = PythonAnalyzer::with_database(Box::new(database))
        .expect("construct analyzer")
        .analyze(directory.path())
        .await
        .expect("analyze package");

    assert_eq!(result.vulnerabilities.len(), 1);
    assert_eq!(
        *observations.calls.lock().expect("read calls"),
        vec![
            (
                "range-dep".to_string(),
                ">=1.2".to_string(),
                "python".to_string()
            ),
            (
                "custom-subject".to_string(),
                "1.0.0".to_string(),
                "python".to_string()
            ),
        ]
    );
    assert_eq!(observations.metadata_calls.load(Ordering::SeqCst), 1);
}
