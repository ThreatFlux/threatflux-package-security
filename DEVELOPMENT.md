# Development Guide

This guide covers the internal structure and design constraints of ThreatFlux Package Security. Contributor workflow and review requirements are in [CONTRIBUTING.md](CONTRIBUTING.md); command-level validation is in [TESTING.md](TESTING.md).

## Toolchain

The repository pins its stable toolchain in `rust-toolchain.toml` and tests the minimum supported Rust version (MSRV) separately. Install Rust through `rustup`, then run:

```bash
rustup show
rustup component add rustfmt clippy llvm-tools-preview
cargo fetch --locked
```

Use the checked-in `Cargo.lock`. Although this repository publishes a library, the lockfile makes CI, audits, examples, and release verification reproducible.

## Architecture

```text
src/
├── lib.rs                 unified package detection and public re-exports
├── analyzers/
│   ├── npm.rs             package.json, dependencies, and scripts
│   ├── python.rs          Python project metadata and setup signals
│   └── java.rs            bounded ZIP-container and manifest inspection
├── core/
│   ├── package.rs         shared traits, metadata, and analysis results
│   ├── dependency.rs      dependency summaries
│   ├── patterns.rs        compiled patterns and evidence
│   ├── risk.rs            aggregate triage scoring
│   └── vulnerability.rs   advisory types and database trait
├── vulnerability_db/      bundled per-ecosystem advisory baselines
└── utils/                 version and package-name helpers
```

`PackageSecurityAnalyzer` routes a caller-selected path to an ecosystem analyzer. `PackageAnalyzer` and `AnalysisResult` provide the shared abstraction, while typed analyzer results retain ecosystem-specific details.

## Design invariants

### Findings are evidence

Names such as `malicious_patterns` are historical API terminology. A match means a rule observed text or metadata; it does not prove malicious intent. New APIs and documentation should prefer “signal,” “match,” or “finding” when that is accurate.

Every detection change should include benign near-miss tests and true-positive tests. Do not improve recall by silently turning common package syntax into high-severity findings.

### Untrusted work is bounded

All bytes, strings, entries, dependency declarations, and output fields derived from a package are attacker-controlled. New parsers must define and test limits before allocating or iterating. Avoid reading an entire file or expanding an archive member before its limit is known.

Reject symlinks for manifest-like inputs unless a future API explicitly documents a safe policy. Java archives are inspected in place; do not extract them to the filesystem.

### Analysis does not execute packages

Never import Python modules, invoke npm lifecycle hooks, load JVM classes, or run build tooling to obtain metadata. Static parsing that cannot answer a question should return an explicit limitation, not cross the execution boundary.

### Built-in data is in-memory and offline

Built-in npm/Python databases are bundled and in memory; Java analysis does not consult one. Default construction and scanning must not acquire network or persistence access.

npm/Python analyzers can inject a `VulnerabilityDatabase`. That implementation is trusted in-process code and may perform arbitrary I/O from `metadata` or `check_package`. The analyzer deliberately does not invent timeout, retry, response-bound, cache, provenance, or cancellation policy for it. New integration behavior must preserve that explicit boundary and surface accurate `DatabaseMetadata` with results.

### Results are reproducible

Sort library-owned results whose source order is not meaningful. Do not expose `HashMap` or filesystem iteration order through evidence arrays, JSON, or scores. An injected vulnerability database owns the order of the records it returns and must make that order stable when reproducibility matters. Tests must not depend on wall-clock time, public services, user cache contents, or locale.

### Errors retain context without echoing hostile input

Errors should identify the operation and bounded field/path context. Avoid copying arbitrarily large manifest content, control characters, or secrets into errors and logs. A failed analysis returns an error rather than a misleading partial “safe” result.

## Adding or changing a parser

1. Define accepted path types and format detection.
2. Identify all reads, allocations, loops, recursion, decompression, and retained output.
3. Add boundary constants or configuration before implementing the happy path.
4. Reject unsupported special files and unsafe archive names early.
5. Test empty, malformed, oversized, non-UTF-8, symlinked, and adversarial inputs.
6. Add benign near-misses for every new security heuristic.
7. Update [docs/BEHAVIOR.md](docs/BEHAVIOR.md) and migration notes if observable behavior changes.

## Adding a built-in pattern

Patterns live in `core::patterns` and must have a stable identifier, category, severity, bounded evidence, and focused scope. Compile regular expressions once during matcher construction.

Required tests include:

- the intended positive case;
- ordinary code that is lexically similar but benign;
- case and Unicode behavior where relevant;
- deterministic evidence order;
- maximum evidence and input boundaries.

Changing a pattern identifier or serialized category is a compatibility change. Record it in the changelog and migration guide.

## Vulnerability data

Bundled records are testable baseline data, not a comprehensive feed. Preserve source-native advisory identity, optional CVE aliases, package ecosystem/name, CVSS source, references, coverage, as-of date, and provenance. Version comparison must follow the supported ecosystem semantics; never compare version strings lexicographically.

Do not add an advisory solely to make a test green. Use a synthetic database implementation in tests when testing matching behavior that does not require a real advisory.

## Documentation

Public rustdoc should describe errors, resource behavior, and security semantics. README snippets must compile. Avoid claims such as “detects malware,” “complete vulnerability coverage,” or “safe package.”

## Release changes

Do not publish routine releases from a workstation. They use the tagged workflow and crates.io trusted publishing described in [docs/RELEASING.md](docs/RELEASING.md). The only exception is the separately controlled, one-time first-publication bootstrap documented there.
