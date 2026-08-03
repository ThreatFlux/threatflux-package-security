use std::fs;
use std::future::Future;
use std::task::{Context, Poll, Waker};
use tempfile::TempDir;
use threatflux_package_security::{PackageSecurityAnalyzer, RiskLevel};

fn write(directory: &TempDir, name: &str, content: impl AsRef<[u8]>) {
    fs::write(directory.path().join(name), content).expect("write test fixture");
}

#[tokio::test]
async fn npm_reports_only_exact_curated_matches_and_tracks_unresolved_ranges() {
    let directory = TempDir::new().expect("temporary directory");
    write(
        &directory,
        "package.json",
        r#"{
          "name": "example-package",
          "version": "1.0.0",
          "homepage": "https://example.invalid",
          "dependencies": {
            "lodash": "4.17.11",
            "axios": "^0.21.0",
            "minimist": "01.2.2"
          },
          "optionalDependencies": {"lodash": "4.17.12"},
          "scripts": {"build": "webpack --mode production"}
        }"#,
    );

    let result = PackageSecurityAnalyzer::new()
        .expect("construct analyzer")
        .analyze(directory.path())
        .await
        .expect("analyze npm project");

    assert_eq!(result.package_info().package_type(), "npm");
    assert!(result.vulnerabilities().is_empty());
    assert_eq!(
        result.dependency_analysis().unresolved_requirements,
        vec!["axios@^0.21.0", "minimist@01.2.2"]
    );
    assert_eq!(result.dependency_analysis().direct_dependencies, 3);
    assert!(result.malicious_patterns().is_empty());
    assert_eq!(result.overall_risk_level(), RiskLevel::Informational);
    assert!(result.quality_metrics().is_none());
    assert_eq!(
        result
            .vulnerability_database_metadata()
            .expect("npm database metadata")
            .as_of
            .as_deref(),
        Some("2026-08-03")
    );
}

#[tokio::test]
async fn npm_strictly_rejects_malformed_supported_fields() {
    for manifest in [
        r#"{"name":"x","version":"1.0.0","scripts":{"test":3}}"#,
        r#"{"name":"x","version":"1.0.0","private":"false"}"#,
        r#"{"name":"x","version":"1.0.0","dependencies":[]}"#,
        r#"{"name":"x","version":"1.0.0","keywords":["ok",2]}"#,
        r#"{"name":" lodash ","version":"4.17.11"}"#,
        r#"{"name":"Uppercase","version":"1.0.0"}"#,
        r#"{"name":"x","version":"=1.0.0"}"#,
        r#"{"name":"x","version":"v1.0.0"}"#,
    ] {
        let directory = TempDir::new().expect("temporary directory");
        write(&directory, "package.json", manifest);
        assert!(
            PackageSecurityAnalyzer::new()
                .expect("construct analyzer")
                .analyze(directory.path())
                .await
                .is_err(),
            "accepted malformed manifest: {manifest}"
        );
    }
}

#[tokio::test]
async fn python_rejects_noncanonical_subject_identity() {
    for (name, version) in [
        (" Django ", "4.2.5"),
        ("Django", "==4.2.5"),
        ("Django", "===4.2.5"),
    ] {
        let directory = TempDir::new().expect("temporary directory");
        write(
            &directory,
            "pyproject.toml",
            format!("[project]\nname = {name:?}\nversion = {version:?}\n"),
        );
        assert!(
            PackageSecurityAnalyzer::new()
                .expect("construct analyzer")
                .analyze(directory.path())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn python_prefers_pyproject_and_parses_pep508_subset_without_guessing_ranges() {
    let directory = TempDir::new().expect("temporary directory");
    write(
        &directory,
        "pyproject.toml",
        r#"
[project]
name = "modern-package"
version = "2.0.0"
dependencies = [
  "Django[argon2]==4.2.5",
  "Flask==0.12.2; python_version < '2'",
  "requests>=2.19",
  "local-package @ https://example.invalid/package.whl",
]
keywords = ["security"]

[project.urls]
Homepage = "https://example.invalid"
"#,
    );
    write(
        &directory,
        "setup.py",
        "from setuptools import setup\nsetup(name='legacy-decoy', version='0.1.0')\n",
    );
    write(&directory, "requirements.txt", "# stale legacy file\n");

    let result = PackageSecurityAnalyzer::new()
        .expect("construct analyzer")
        .analyze(directory.path())
        .await
        .expect("analyze Python project");

    assert_eq!(result.package_info().name(), "modern-package");
    assert_eq!(result.vulnerabilities().len(), 1);
    assert_eq!(
        result.dependency_analysis().dependency_tree[0].is_direct,
        Some(true)
    );
    assert_eq!(
        result.vulnerabilities()[0].advisory_id(),
        "GHSA-h8gc-pgj2-vjm3"
    );
    assert_eq!(
        result.dependency_analysis().unresolved_requirements,
        vec![
            "Flask==0.12.2; python_version < '2'",
            "local-package @ https://example.invalid/package.whl",
            "requests>=2.19"
        ]
    );
}

#[tokio::test]
async fn subject_and_dependency_advisories_are_distinguished_and_deduplicated() {
    let npm = TempDir::new().expect("temporary directory");
    write(
        &npm,
        "package.json",
        r#"{"name":"lodash","version":"4.17.11","dependencies":{"lodash":"4.17.11"}}"#,
    );
    let npm_result = PackageSecurityAnalyzer::new()
        .expect("construct analyzer")
        .analyze(npm.path())
        .await
        .expect("analyze npm subject");
    assert_eq!(npm_result.subject_vulnerabilities().len(), 1);
    assert_eq!(npm_result.vulnerabilities().len(), 1);
    assert_eq!(
        npm_result
            .dependency_analysis()
            .vulnerability_summary
            .total_vulnerabilities,
        1
    );

    let python = TempDir::new().expect("temporary directory");
    write(
        &python,
        "pyproject.toml",
        r#"
[project]
name = "PyYAML"
version = "5.3.1"
dependencies = ["PyYAML==5.3.1"]
"#,
    );
    let python_result = PackageSecurityAnalyzer::new()
        .expect("construct analyzer")
        .analyze(python.path())
        .await
        .expect("analyze Python subject");
    assert_eq!(python_result.subject_vulnerabilities().len(), 1);
    assert_eq!(python_result.vulnerabilities().len(), 1);
    assert_eq!(
        python_result
            .dependency_analysis()
            .vulnerability_summary
            .total_vulnerabilities,
        1
    );
}

#[tokio::test]
async fn npm_preserves_distinct_roles_and_models_optional_override() {
    let roles = TempDir::new().expect("temporary directory");
    write(
        &roles,
        "package.json",
        r#"{
          "name":"role-test",
          "version":"1.0.0",
          "dependencies":{"lodash":"4.17.11"},
          "devDependencies":{"lodash":"4.17.21"}
        }"#,
    );
    let result = PackageSecurityAnalyzer::new()
        .expect("construct analyzer")
        .analyze(roles.path())
        .await
        .expect("analyze npm roles");
    assert_eq!(result.dependency_analysis().dependency_tree.len(), 2);
    assert_eq!(result.vulnerabilities().len(), 1);

    let optional = TempDir::new().expect("temporary directory");
    write(
        &optional,
        "package.json",
        r#"{
          "name":"optional-test",
          "version":"1.0.0",
          "dependencies":{"lodash":"4.17.11"},
          "optionalDependencies":{"lodash":"4.17.21"}
        }"#,
    );
    let result = PackageSecurityAnalyzer::new()
        .expect("construct analyzer")
        .analyze(optional.path())
        .await
        .expect("analyze optional override");
    assert_eq!(result.dependency_analysis().dependency_tree.len(), 1);
    assert!(result.vulnerabilities().is_empty());
}

#[tokio::test]
async fn lifecycle_and_custom_setup_hooks_are_observable_supply_chain_signals() {
    let npm = TempDir::new().expect("temporary directory");
    write(
        &npm,
        "package.json",
        r#"{"name":"hook-test","version":"1.0.0","scripts":{"install":"node install.js"}}"#,
    );
    let npm_result = PackageSecurityAnalyzer::new()
        .expect("construct analyzer")
        .analyze(npm.path())
        .await
        .expect("analyze npm hook");
    assert_eq!(
        npm_result
            .risk_assessment()
            .risk_score
            .components
            .get("supply_chain"),
        Some(&10.0)
    );
    assert!(
        npm_result
            .risk_assessment()
            .security_posture
            .supply_chain_risks
    );

    let suspicious = TempDir::new().expect("temporary directory");
    write(
        &suspicious,
        "package.json",
        r#"{"name":"script-test","version":"1.0.0","scripts":{"test":"curl https://example.invalid"}}"#,
    );
    let suspicious_result = PackageSecurityAnalyzer::new()
        .expect("construct analyzer")
        .analyze(suspicious.path())
        .await
        .expect("analyze suspicious non-install script");
    assert!(
        suspicious_result
            .risk_assessment()
            .security_posture
            .supply_chain_risks
    );

    let python = TempDir::new().expect("temporary directory");
    write(
        &python,
        "setup.py",
        "from setuptools import setup\nsetup(name='hook-test', version='1.0.0', cmdclass={'install': object})\n",
    );
    let python_result = PackageSecurityAnalyzer::new()
        .expect("construct analyzer")
        .analyze(python.path())
        .await
        .expect("analyze setup hook");
    assert_eq!(
        python_result
            .risk_assessment()
            .risk_score
            .components
            .get("supply_chain"),
        Some(&15.0)
    );
    assert!(
        python_result
            .risk_assessment()
            .security_posture
            .supply_chain_risks
    );
}

#[tokio::test]
async fn requirements_file_dependencies_have_unknown_role_and_directness() {
    let directory = TempDir::new().expect("temporary directory");
    write(
        &directory,
        "setup.py",
        "from setuptools import setup\nsetup(name='legacy', version='1.0.0')\n",
    );
    write(&directory, "requirements.txt", "Django==4.2.5\t# pinned\n");
    let result = PackageSecurityAnalyzer::new()
        .expect("construct analyzer")
        .analyze(directory.path())
        .await
        .expect("analyze requirements file");
    let dependency = &result.dependency_analysis().dependency_tree[0];
    assert_eq!(dependency.is_direct, None);
    assert_eq!(dependency.is_dev, None);
    assert_eq!(result.dependency_analysis().direct_dependencies, 0);
    assert_eq!(result.vulnerabilities().len(), 1);
}

#[tokio::test]
async fn build_only_pyproject_falls_back_to_legacy_metadata() {
    let directory = TempDir::new().expect("temporary directory");
    write(
        &directory,
        "pyproject.toml",
        "[build-system]\nrequires = ['setuptools']\nbuild-backend = 'setuptools.build_meta'\n",
    );
    write(
        &directory,
        "setup.cfg",
        "[metadata]\nName = legacy-project\nVersion = 1.2.3\n",
    );
    let result = PackageSecurityAnalyzer::new()
        .expect("construct analyzer")
        .analyze(directory.path())
        .await
        .expect("analyze legacy metadata");
    assert_eq!(result.package_info().name(), "legacy-project");
}

#[tokio::test]
async fn setup_cfg_rejects_case_insensitive_duplicate_identity_metadata() {
    for content in [
        "[metadata]\nname = first\nName = second\nversion = 1.0.0\n",
        "[metadata]\nname = first\nversion = 1.0.0\n[METADATA]\nname = second\n",
    ] {
        let directory = TempDir::new().expect("temporary directory");
        write(&directory, "setup.cfg", content);
        assert!(
            PackageSecurityAnalyzer::new()
                .expect("construct analyzer")
                .analyze(directory.path())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn setup_field_parser_ignores_comments_and_longer_identifier_decoys() {
    let directory = TempDir::new().expect("temporary directory");
    write(
        &directory,
        "setup.py",
        r#"
from setuptools import setup
# name="comment-decoy"
long_name="identifier-decoy"
setup(name="actual-name", version="1.0.0")
"#,
    );

    let result = PackageSecurityAnalyzer::new()
        .expect("construct analyzer")
        .analyze(directory.path())
        .await
        .expect("analyze setup.py project");
    assert_eq!(result.package_info().name(), "actual-name");
}

#[tokio::test]
async fn malformed_python_requirements_do_not_become_advisory_matches() {
    let directory = TempDir::new().expect("temporary directory");
    write(
        &directory,
        "pyproject.toml",
        r#"
[project]
name = "malformed-requirements"
version = "1.0.0"
dependencies = ["Django[???]==4.2.5", "PyYAML=5.3.1"]
"#,
    );

    let result = PackageSecurityAnalyzer::new()
        .expect("construct analyzer")
        .analyze(directory.path())
        .await
        .expect("analyze Python project");
    assert!(result.vulnerabilities().is_empty());
    assert_eq!(
        result.dependency_analysis().unresolved_requirements,
        vec!["Django[???]==4.2.5", "PyYAML=5.3.1"]
    );
}

#[tokio::test]
async fn duplicate_python_requirements_do_not_inflate_advisory_risk() {
    let directory = TempDir::new().expect("temporary directory");
    write(
        &directory,
        "pyproject.toml",
        r#"
[project]
name = "duplicate-requirements"
version = "1.0.0"
dependencies = ["Django==4.2.5", "django==4.2.5", "DJANGO==4.2.5"]
"#,
    );

    let result = PackageSecurityAnalyzer::new()
        .expect("construct analyzer")
        .analyze(directory.path())
        .await
        .expect("analyze Python project");
    assert_eq!(result.vulnerabilities().len(), 1);
    assert_eq!(
        result
            .dependency_analysis()
            .vulnerability_summary
            .total_vulnerabilities,
        1
    );
    assert_eq!(result.risk_assessment().risk_score.total_score, 60.0);
}

#[tokio::test]
async fn network_capability_alone_is_not_labeled_code_execution() {
    let directory = TempDir::new().expect("temporary directory");
    write(
        &directory,
        "setup.py",
        r#"
import requests
from setuptools import setup
requests.get("https://example.invalid")
setup(name="network-client", version="1.0.0")
"#,
    );

    let result = PackageSecurityAnalyzer::new()
        .expect("construct analyzer")
        .analyze(directory.path())
        .await
        .expect("analyze setup.py project");
    assert!(!result.risk_assessment().security_posture.supply_chain_risks);
    assert!(result.overall_risk_level() < RiskLevel::High);
}

#[tokio::test]
async fn setup_comments_and_string_literals_are_not_executable_signals() {
    let directory = TempDir::new().expect("temporary directory");
    write(
        &directory,
        "setup.py",
        r#"
from setuptools import setup
# eval("comment only")
EXAMPLE = "os.system('literal only')"
DOCS = '''subprocess.run(["literal only"])'''
setup(name="benign-package", version="1.0.0")
"#,
    );

    let result = PackageSecurityAnalyzer::new()
        .expect("construct analyzer")
        .analyze(directory.path())
        .await
        .expect("analyze setup.py project");
    assert!(result.malicious_patterns().is_empty());
    assert!(!result.risk_assessment().security_posture.supply_chain_risks);
    assert_eq!(result.overall_risk_level(), RiskLevel::Informational);
}

#[tokio::test]
async fn benign_python_identifier_substrings_are_not_execution_signals() {
    let directory = TempDir::new().expect("temporary directory");
    write(
        &directory,
        "setup.py",
        r#"
from setuptools import setup
import os
import subprocess
def preval():
    return 1
def myexec():
    return 2
environment = os.getenv("PATH")
setup(name="benign-identifiers", version="1.0.0")
"#,
    );
    let result = PackageSecurityAnalyzer::new()
        .expect("construct analyzer")
        .analyze(directory.path())
        .await
        .expect("analyze benign identifiers");
    assert!(result.malicious_patterns().is_empty());
    assert!(!result.risk_assessment().security_posture.supply_chain_risks);
}

#[tokio::test]
async fn setup_parser_rejects_decoys_and_dynamic_subject_metadata() {
    let decoy = TempDir::new().expect("temporary directory");
    write(
        &decoy,
        "setup.py",
        r#"
from setuptools import setup
DECOY = "name='django', version='4.2.5'"
unrelated_name = "also-a-decoy"
setup(name="actual-package", version="1.0.0", keywords=["security"])
"#,
    );
    let result = PackageSecurityAnalyzer::new()
        .expect("construct analyzer")
        .analyze(decoy.path())
        .await
        .expect("analyze static setup call");
    assert_eq!(result.package_info().name(), "actual-package");
    assert!(result.subject_vulnerabilities().is_empty());

    for dynamic_name in [
        r#""django" if condition else "clean""#,
        r#""django" + suffix"#,
        r#""django" "clean""#,
    ] {
        let directory = TempDir::new().expect("temporary directory");
        write(
            &directory,
            "setup.py",
            format!("from setuptools import setup\nsetup(name={dynamic_name}, version='4.2.5')\n"),
        );
        assert!(
            PackageSecurityAnalyzer::new()
                .expect("construct analyzer")
                .analyze(directory.path())
                .await
                .is_err(),
            "accepted dynamic setup name: {dynamic_name}"
        );
    }
}

#[tokio::test]
async fn executable_f_string_expressions_remain_visible_to_setup_scanning() {
    let directory = TempDir::new().expect("temporary directory");
    write(
        &directory,
        "setup.py",
        r#"
from setuptools import setup
setup(name="formatted-expression", version="1.0.0")
message = f"literal eval( text {{escaped}} {eval(payload)}"
"#,
    );
    let result = PackageSecurityAnalyzer::new()
        .expect("construct analyzer")
        .analyze(directory.path())
        .await
        .expect("analyze formatted expression");
    assert!(result.risk_assessment().security_posture.supply_chain_risks);
    assert!(
        result
            .malicious_patterns()
            .iter()
            .any(|pattern| pattern.pattern_id == "EXEC_001")
    );
}

#[tokio::test]
async fn parse_errors_do_not_echo_attacker_controlled_toml() {
    let directory = TempDir::new().expect("temporary directory");
    let marker = "DO_NOT_ECHO_SECRET_MARKER";
    write(
        &directory,
        "pyproject.toml",
        format!(
            "[project]\nname = \"safe-name\" {}\nversion = \"1.0.0\"\n",
            marker.repeat(2_000)
        ),
    );
    let error = PackageSecurityAnalyzer::new()
        .expect("construct analyzer")
        .analyze(directory.path())
        .await
        .err()
        .expect("malformed TOML must fail")
        .to_string();
    assert!(!error.contains(marker));
    assert!(error.len() < 256);
}

#[test]
fn analysis_without_tokio_returns_an_error_instead_of_panicking() {
    let directory = TempDir::new().expect("temporary directory");
    write(
        &directory,
        "package.json",
        r#"{"name":"runtime-test","version":"1.0.0"}"#,
    );
    let analyzer = PackageSecurityAnalyzer::new().expect("construct analyzer");
    let mut future = Box::pin(analyzer.analyze(directory.path()));
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    match Future::poll(future.as_mut(), &mut context) {
        Poll::Ready(Err(error)) => assert!(error.to_string().contains("Tokio runtime")),
        Poll::Ready(Ok(_)) => panic!("analysis unexpectedly succeeded without Tokio"),
        Poll::Pending => panic!("runtime guard did not resolve on the first poll"),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn caller_controlled_paths_are_escaped_in_errors() {
    let directory = TempDir::new().expect("temporary directory");
    let path = directory.path().join("line\n\u{1b}[2J.unknown");
    write(&directory, "line\n\u{1b}[2J.unknown", b"input");
    let error = PackageSecurityAnalyzer::new()
        .expect("construct analyzer")
        .analyze(&path)
        .await
        .err()
        .expect("unknown input must fail")
        .to_string();
    assert!(!error.contains('\n'));
    assert!(!error.contains('\u{1b}'));
    assert!(error.contains("\\n"));
}

#[tokio::test]
async fn project_metadata_size_and_symlink_boundaries_fail_closed() {
    let oversized = TempDir::new().expect("temporary directory");
    write(
        &oversized,
        "package.json",
        vec![b' '; threatflux_package_security::limits::MAX_PROJECT_FILE_BYTES as usize + 1],
    );
    assert!(
        PackageSecurityAnalyzer::new()
            .expect("construct analyzer")
            .analyze(oversized.path())
            .await
            .is_err()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let symlinked = TempDir::new().expect("temporary directory");
        let target = symlinked.path().join("target.json");
        fs::write(&target, r#"{"name":"x","version":"1.0.0"}"#).expect("write target");
        symlink(&target, symlinked.path().join("package.json")).expect("create symlink");
        assert!(
            PackageSecurityAnalyzer::new()
                .expect("construct analyzer")
                .analyze(symlinked.path())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn npm_and_python_archives_are_not_advertised_as_supported() {
    let analyzer = PackageSecurityAnalyzer::new().expect("construct analyzer");
    assert!(analyzer.analyze("package.tgz").await.is_err());
    assert!(analyzer.analyze("package.whl").await.is_err());
}

#[tokio::test]
async fn unified_analyzer_rejects_multi_ecosystem_directories() {
    let directory = TempDir::new().expect("temporary directory");
    write(
        &directory,
        "package.json",
        r#"{"name":"npm-side","version":"1.0.0"}"#,
    );
    write(
        &directory,
        "pyproject.toml",
        "[project]\nname = 'python-side'\nversion = '1.0.0'\n",
    );
    let error = PackageSecurityAnalyzer::new()
        .expect("construct analyzer")
        .analyze(directory.path())
        .await
        .err()
        .expect("ambiguous input must fail");
    assert!(error.to_string().contains("Ambiguous package input"));
}
