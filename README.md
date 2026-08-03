# ThreatFlux Package Security

[![CI](https://github.com/ThreatFlux/threatflux-package-security/actions/workflows/ci.yml/badge.svg)](https://github.com/ThreatFlux/threatflux-package-security/actions/workflows/ci.yml)
[![Security](https://github.com/ThreatFlux/threatflux-package-security/actions/workflows/security.yml/badge.svg)](https://github.com/ThreatFlux/threatflux-package-security/actions/workflows/security.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.95-blue.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`threatflux-package-security` is a Rust library for inspecting package metadata and surfacing review signals across npm, Python, and Java package inputs. It combines manifest parsing, a bundled vulnerability baseline, suspicious-text heuristics, dependency summaries, and package-name similarity into a common result model.

The output is evidence for a security review—not a malware verdict, vulnerability-completeness guarantee, or substitute for sandboxing and provenance verification.

> The crate is pre-1.0. Version 0.2 introduces intentional compatibility changes; see the [migration guide](docs/MIGRATING_TO_0.2.md).

## What it analyzes

| Ecosystem | Accepted input                                                                | Current analysis                                                                                                           |
| --------- | ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| npm       | An unpacked directory containing `package.json`                               | Metadata, declared dependencies, lifecycle-script signals, subject/dependency advisory matches, and name similarity        |
| Python    | An unpacked directory containing `pyproject.toml`, `setup.cfg`, or `setup.py` | Static metadata, supported requirements, `setup.py` text signals, subject/dependency advisory matches, and name similarity |
| Java      | `.jar`, `.war`, `.ear`, `.apk`, or `.aar` ZIP-compatible archives             | Manifest metadata, signature-entry presence, and native-library presence                                                   |

Important limitations:

- npm tarballs and Python wheels/source archives are not accepted as direct inputs in 0.2. Unpack them into a controlled directory first.
- Java analysis does not decompile class files, resolve Maven/Gradle dependency graphs, validate signing certificates, or attest publisher identity.
- Java analysis does not infer package coordinates, query an advisory database, or scan manifest text as executable code; its vulnerability and pattern result lists are empty in 0.2.
- Dependency analysis covers declarations the parser understands; it is not a complete lockfile or transitive dependency resolver.
- The bundled vulnerability records are a small offline baseline, not a live advisory service. An empty result does not establish that a package is vulnerability-free.
- Bundled advisory matching requires an exact subject or dependency version. Ranges, tags, URLs, wildcards, and unresolved declarations are not reported as confirmed built-in matches.
- Pattern and typosquatting matches are heuristic and may produce both false positives and false negatives.

See [Behavior and guarantees](docs/BEHAVIOR.md) for the precise contract.

## Install

The crate has not yet been published to crates.io. Until the first release, pin a reviewed full commit SHA:

```toml
[dependencies]
threatflux-package-security = { git = "https://github.com/ThreatFlux/threatflux-package-security", rev = "<full-commit-sha>" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

After 0.2.0 is published, applications can use `threatflux-package-security = "0.2"` from crates.io.

The minimum supported Rust version is 1.95. Applications should commit their `Cargo.lock` and use `--locked` in CI.

## Quick start

```rust,no_run
use std::path::Path;
use threatflux_package_security::PackageSecurityAnalyzer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let analyzer = PackageSecurityAnalyzer::new()?;
    let result = analyzer.analyze(Path::new("./fixtures/npm-package")).await?;

    println!(
        "{} {}: {} ({:.1}/100)",
        result.package_info().name().escape_default(),
        result.package_info().metadata().version.escape_default(),
        result.overall_risk_level(),
        result.risk_assessment().risk_score.total_score,
    );

    for vulnerability in result.vulnerabilities() {
        let cve = vulnerability.cve_id().unwrap_or("no CVE alias");
        println!(
            "{} ({}) [{}] {}",
            vulnerability.advisory_id().escape_default(),
            cve.escape_default(),
            vulnerability.severity,
            vulnerability.title.escape_default(),
        );
    }

    println!(
        "subject matches: {}; dependency matches: {}",
        result.subject_vulnerabilities().len(),
        result.dependency_analysis().vulnerability_summary.total_vulnerabilities,
    );

    for signal in result.malicious_patterns() {
        println!("{}: {:?}", signal.pattern_id.escape_default(), signal.evidence);
    }

    if let Some(database) = result.vulnerability_database_metadata() {
        println!(
            "advisory coverage: {:?} ({})",
            database.coverage,
            database.name.escape_default(),
        );
    }

    Ok(())
}
```

Run the complete example against a package you control:

```bash
cargo run --example basic_usage -- ./path/to/unpacked/package
```

## Choosing an analyzer explicitly

The unified analyzer detects an ecosystem from the path and fails closed when a directory advertises multiple supported ecosystems. Use an ecosystem analyzer when mixed metadata is intentional, when the caller already knows the input type, or when it needs a typed result:

```rust,no_run
use std::path::Path;
use threatflux_package_security::{NpmAnalyzer, PackageAnalyzer};

# async fn inspect() -> Result<(), Box<dyn std::error::Error>> {
let analyzer = NpmAnalyzer::new()?;
let result = analyzer.analyze(Path::new("./fixtures/npm-package")).await?;

println!("install hooks: {}", result.scripts_analysis.has_install_scripts);
println!("direct dependencies: {}", result.dependency_analysis.direct_dependencies);
# Ok(())
# }
```

`PackageAnalyzer` must be in scope to call the trait method on an ecosystem analyzer. Analysis futures must be polled from an active Tokio runtime; a missing runtime returns an error.

Treat returned errors as opaque and do not branch on their display text; a structured error taxonomy is planned as a focused post-0.2 API change.

## Application-provided vulnerability databases

`NpmAnalyzer::with_database` and `PythonAnalyzer::with_database` accept a boxed `VulnerabilityDatabase`. `PackageSecurityAnalyzer::with_vulnerability_databases` injects both at once and retains the standard Java analyzer; `from_analyzers` composes already configured ecosystem analyzers.

After npm/Python input parsing and validation, `check_package` is awaited sequentially for parsed unmarked dependencies and the exact subject package. The synchronous `metadata` method is read only while assembling a successful result. It must still be cheap, nonblocking, and side-effect free. The injection interface has no mutable update operation, and the analyzer does not add a timeout, retry failures, cap records returned by the implementation, or isolate its I/O and side effects. A database error fails the entire analysis.

An injected database is therefore trusted in-process application code. It owns network authentication, redirects, timeouts, retries, response and result-size bounds, schema validation, freshness, provenance, persistence, cancellation behavior, and package-version semantics. A timeout around the async analysis cannot preempt blocking work inside synchronous `metadata`. Its `DatabaseMetadata` is exposed through `AnalysisResult::vulnerability_database_metadata`; applications should provide accurate coverage and provenance rather than implying completeness.

Java has no database-injection constructor in 0.2 because the analyzer does not derive authoritative Maven coordinates from an archive filename or manifest.

## Custom patterns

`core::PatternMatcher::with_patterns` compiles an application-provided pattern set. Indicators are case-sensitive literals. Empty literals/file patterns, empty or invalid regular expressions, caller-supplied definition evidence, and over-limit collections fail construction:

```rust
use threatflux_package_security::core::{MaliciousPattern, PatternMatcher};
use threatflux_package_security::core::patterns::{PatternCategory, PatternSeverity};

let matcher = PatternMatcher::with_patterns(vec![MaliciousPattern {
    pattern_id: "ORG_001".into(),
    pattern_name: "Unapproved install endpoint".into(),
    description: "Flags an organization-specific endpoint".into(),
    category: PatternCategory::NetworkAccess,
    severity: PatternSeverity::High,
    indicators: vec!["packages.example.invalid".into()],
    regex_patterns: vec![r"https://packages\.example\.invalid/".into()],
    file_patterns: vec![],
    evidence: vec![],
}])?;

let findings = matcher.scan(
    "curl https://packages.example.invalid/bootstrap.sh",
    Some("package.json"),
)?;
assert_eq!(findings.len(), 1);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Custom regular expressions are trusted, in-process inputs. Compile patterns outside request hot paths, handle the fallible `scan` result, add application-level bounds around scanned work, and review pattern changes like code.

## Reading results safely

- Treat `RiskLevel` and `total_score` as triage aids. Preserve the underlying evidence for review.
- `Informational` is only the lowest triage bucket. It does not imply complete coverage or prove safety.
- Validate a vulnerability against an authoritative advisory source and the package ecosystem’s version semantics before remediation.
- Use `subject_vulnerabilities()` for subject-only matches. `vulnerabilities()` is the canonical deduplicated subject/dependency union; the dependency summary remains dependency-only.
- Do not execute install scripts or package code as part of inspection. This library parses text and archive metadata; execution belongs in a separate sandboxed workflow if it is required at all.
- Reject or isolate untrusted filesystem paths and enforce input-size, file-count, time, and memory limits around the library.

## Network and filesystem behavior

Built-in npm/Python analysis uses small in-memory advisory snapshots and does not perform network requests or persist advisory data. Java analysis does not consult a vulnerability database. The embedded databases cannot be updated.

The caller owns:

- path authorization and symlink policy;
- archive provenance and additional resource limits;
- network, timeout, result-bound, and persistence behavior of injected databases;
- isolation of untrusted custom patterns or database implementations.

Injecting a database broadens the analysis boundary: its `check_package` implementation can use the network or perform arbitrary side effects. The host application and other dependencies can do the same. See [Security boundaries](SECURITY.md).

## Documentation

- [Behavior and guarantees](docs/BEHAVIOR.md)
- [Migration to 0.2](docs/MIGRATING_TO_0.2.md)
- [Testing](TESTING.md)
- [Development](DEVELOPMENT.md)
- [Contributing](CONTRIBUTING.md)
- [Release process](docs/RELEASING.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

## Support

Use [GitHub Issues](https://github.com/ThreatFlux/threatflux-package-security/issues) for reproducible defects, documentation questions, and feature requests. Report vulnerabilities privately according to [SECURITY.md](SECURITY.md).

## License

Licensed under the [MIT License](LICENSE).
