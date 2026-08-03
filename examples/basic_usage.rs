//! Analyze one local package path and print a human-reviewable summary.
//!
//! Run with:
//! `cargo run --example basic_usage -- ./path/to/unpacked/package`

use std::io;
use std::path::PathBuf;
use threatflux_package_security::PackageSecurityAnalyzer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "usage: cargo run --example basic_usage -- <package-path>",
            )
        })?;

    let analyzer = PackageSecurityAnalyzer::new()?;
    let result = analyzer.analyze(&path).await?;
    let package = result.package_info();
    let assessment = result.risk_assessment();

    println!("package: {}", package.name().escape_default());
    println!("version: {}", package.metadata().version.escape_default());
    println!("ecosystem: {}", package.package_type().escape_default());
    println!("risk level: {}", assessment.risk_score.risk_level);
    println!("risk score: {:.1}/100", assessment.risk_score.total_score);
    println!(
        "direct dependencies: {}",
        result.dependency_analysis().direct_dependencies
    );

    if result.vulnerabilities().is_empty() {
        println!("vulnerability baseline matches: none");
    } else {
        println!("vulnerability baseline matches:");
        for vulnerability in result.vulnerabilities() {
            let cve = vulnerability.cve_id().unwrap_or("no CVE alias");
            println!(
                "  - {} ({}) [{}]: {}",
                vulnerability.advisory_id().escape_default(),
                cve.escape_default(),
                vulnerability.severity,
                vulnerability.title.escape_default(),
            );
        }
    }

    if result.malicious_patterns().is_empty() {
        println!("heuristic pattern matches: none");
    } else {
        println!("heuristic pattern matches:");
        for finding in result.malicious_patterns() {
            println!(
                "  - {} [{:?}]: {}",
                finding.pattern_id.escape_default(),
                finding.severity,
                finding.pattern_name.escape_default(),
            );
            for evidence in &finding.evidence {
                println!("      {}", evidence.escape_default());
            }
        }
    }

    if let Some(risk) = result.typosquatting_risk() {
        println!(
            "name-similarity signal: {} (confidence {:.2})",
            risk.is_potential_typosquatting, risk.confidence_score
        );
        if !risk.similar_packages.is_empty() {
            let names = risk
                .similar_packages
                .iter()
                .map(|name| name.escape_default().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            println!("similar package names: {names}");
        }
    }

    if let Some(database) = result.vulnerability_database_metadata() {
        println!(
            "advisory database: {} ({:?}, as of {:?})",
            database.name.escape_default(),
            database.coverage,
            database.as_of,
        );
    } else {
        println!("advisory database: not consulted");
    }

    println!("\nReview the evidence before making a security decision.");
    Ok(())
}
