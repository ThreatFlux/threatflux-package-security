# ThreatFlux Package Security Library

A unified security analysis framework for package managers including npm, Python (PyPI), and Java (Maven/Gradle).

## Features

- **Multi-ecosystem support**: Analyze packages from npm, PyPI, Maven/Gradle
- **Vulnerability detection**: Check against comprehensive vulnerability databases
- **Malicious pattern detection**: Identify suspicious code patterns and behaviors
- **Typosquatting detection**: Detect packages with names similar to popular packages
- **Risk scoring**: Unified risk assessment across all package types
- **Dependency analysis**: Deep analysis of package dependencies
- **Supply chain security**: Detect installation scripts and build-time risks

## Installation

```toml
[dependencies]
threatflux-package-security = "0.1.0"
```

## Usage

### Basic Usage

```rust
use threatflux_package_security::PackageSecurityAnalyzer;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create analyzer
    let analyzer = PackageSecurityAnalyzer::new()?;
    
    // Analyze a package
    let result = analyzer.analyze(Path::new("path/to/package")).await?;
    
    // Check risk level
    println!("Risk Level: {:?}", result.risk_assessment().risk_score.risk_level);
    
    // Check vulnerabilities
    for vuln in result.vulnerabilities() {
        println!("Vulnerability: {} - {}", vuln.id, vuln.title);
    }
    
    Ok(())
}
```

### Analyze Specific Package Types

```rust
use threatflux_package_security::analyzers::{NpmAnalyzer, PythonAnalyzer, JavaAnalyzer};

// NPM packages
let npm_analyzer = NpmAnalyzer::new()?;
let npm_result = npm_analyzer.analyze(Path::new("package.json")).await?;

// Python packages
let python_analyzer = PythonAnalyzer::new()?;
let python_result = python_analyzer.analyze(Path::new("setup.py")).await?;

// Java packages
let java_analyzer = JavaAnalyzer::new()?;
let java_result = java_analyzer.analyze(Path::new("app.jar")).await?;
```

## Supported Package Formats

### NPM
- `package.json` directories
- `.tgz` archives
- `npm-shrinkwrap.json` support (planned)

### Python
- `setup.py` projects
- `pyproject.toml` projects
- `.whl` wheel packages
- `.tar.gz` source distributions
- `.egg` packages

### Java
- `.jar` Java Archives
- `.war` Web Application Archives
- `.ear` Enterprise Application Archives
- `.apk` Android Packages
- `.aar` Android Archive Libraries

## Risk Assessment

The library provides a unified risk scoring system:

- **Safe** (0-20): No significant risks detected
- **Low** (20-40): Minor issues that should be reviewed
- **Medium** (40-60): Moderate risks requiring attention
- **High** (60-80): Significant security concerns
- **Critical** (80-100): Severe security issues, immediate action required

## Security Checks

### Vulnerability Detection
- CVE database lookups
- Version-specific vulnerability matching
- Transitive dependency scanning

### Malicious Pattern Detection
- Code execution patterns
- Data exfiltration attempts
- Backdoor indicators
- Cryptocurrency mining
- Obfuscation techniques

### Supply Chain Risks
- Installation script analysis
- Build-time code execution
- External resource downloads
- Suspicious maintainer activity

## Contributing

Contributions are welcome! Please see CONTRIBUTING.md for guidelines.

## License

This project is licensed under MIT.