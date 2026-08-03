# Migrating to 0.2

Version 0.2 is a deliberate pre-1.0 compatibility boundary. It corrects unsupported input claims, hardens untrusted file handling, and makes fallible construction explicit.

## Toolchain

The minimum supported Rust version is 1.95. Update CI and local toolchains before changing the dependency:

```bash
rustup toolchain install 1.95.0 --profile minimal
cargo +1.95.0 test --all-targets --all-features --locked
```

## Dependency update

```toml
[dependencies]
threatflux-package-security = "0.2"
```

Commit the resulting `Cargo.lock` in applications and executables.

## Construction is fallible

`PackageSecurityAnalyzer` no longer implements `Default`. Replace infallible/default construction with error propagation:

```rust,ignore
// 0.1
let analyzer = PackageSecurityAnalyzer::default();

// 0.2
let analyzer = PackageSecurityAnalyzer::new()?;
```

This prevents initialization failures from becoming panics.

The unused `AnalysisOptions` type was removed. It never controlled analyzer behavior; callers should enforce elapsed-time and concurrency policy around the analysis future.

The intentionally incomplete embedded-snapshot version parser is no longer public API. Use the ecosystem's standard version library when application code needs general npm or Python version semantics.

## Supplying vulnerability data

Path-based database constructors were removed because they did not load the supplied path. Version 0.2 instead injects an implementation explicitly:

```rust,ignore
let npm = NpmAnalyzer::with_database(Box::new(my_npm_database))?;
let python = PythonAnalyzer::with_database(Box::new(my_python_database))?;

let analyzer = PackageSecurityAnalyzer::with_vulnerability_databases(
    Box::new(my_other_npm_database),
    Box::new(my_other_python_database),
)?;
```

`PackageSecurityAnalyzer::from_analyzers` can compose already configured npm, Python, and Java analyzers. Java has no database-injection constructor in 0.2.

Injected npm/Python databases run in process. After parsing and validating input, the analyzer awaits `check_package` sequentially for parsed unmarked dependencies and the exact subject package, then reads synchronous `metadata` while assembling a successful result. It adds no timeouts, retries, output caps, or I/O isolation. `metadata` must not block or have side effects. Implementations must enforce async policies themselves; an outer async timeout cannot preempt synchronous blocking work. Any database error fails the analysis. The minimal injection trait has no mutable update operation.

## Input support is stricter

The 0.1 detection helpers advertised npm and Python archive extensions even though their analyzers could not process those files. Version 0.2 accepts npm and Python project directories only.

```rust,ignore
// Unpack in an isolated, resource-bounded workflow first, then analyze the directory.
let result = analyzer.analyze("./unpacked-package").await?;
```

Java continues to accept ZIP-compatible `.jar`, `.war`, `.ear`, `.apk`, and `.aar` files, but rejects encrypted entries, unsafe member paths, symlinked input, malformed containers, and archives that exceed inspection limits. Code that previously passed arbitrary or very large archives must handle these errors.

Analysis futures require an active Tokio runtime. Polling one without a runtime now returns an error instead of allowing Tokio filesystem or blocking-task APIs to panic.

The unified analyzer now rejects directories that advertise multiple supported ecosystems instead of silently preferring npm over Python. Call the typed ecosystem analyzer when mixed metadata is intentional.

Python metadata precedence is now explicit: a valid `pyproject.toml` with `[project]` wins; a valid build-only file falls through to `setup.cfg`, then `setup.py`; malformed TOML fails closed. `[project].dependencies` wins whenever the key exists, otherwise `requirements.txt` is the fallback. Static `setup.py` metadata must come from one unambiguous `setup()` call with simple string name/version values; dynamic expressions are rejected.

## Filesystem behavior

Manifest-like files must be regular files and are not followed through symlinks. If an application intentionally supported symlinked package metadata, resolve and authorize a safe copy before calling the analyzer. Do not weaken the analyzer boundary by resolving package-controlled links in place.

Public errors remain opaque in 0.2. Propagate or display them safely; do not branch on `Display` text. A structured, non-exhaustive error taxonomy is reserved for a focused follow-up API change.

## Advisory behavior

The built-in npm/Python databases are explicitly in-memory, offline, curated-partial snapshots. The standalone updater module, `UpdateConfig`, `UpdateResult`, `update_all_databases`, custom-path constructors, analyzer `with_db_path` constructors, and mutable update methods were removed rather than pretending to load or update persistent data. Java analysis does not consult an advisory database.

Rebaseline vulnerability expectations: the built-in 0.2 databases apply normalized ecosystem names and require a supported exact subject or dependency version instead of treating every record for a package name as a match. Ranges, wildcards, tags, URLs, and malformed requirements are not confirmed built-in matches; application-provided databases define their own version semantics. Embedded affected ranges represent advisory introduced/fixed events and include prereleases by version precedence rather than applying dependency-specifier prerelease filtering. Confirm the resolved version separately when a manifest contains a range rather than a concrete version.

The incorrect 0.1 `event-stream`/CVE-2018-25032 and `ua-parser-js`/CVE-2021-25033 mappings were removed. If persisted findings include either pair, invalidate or re-run them rather than carrying the old association forward.

### Vulnerability identity and database coverage

`Vulnerability::id` was replaced by source-native identity plus an optional alias:

- `advisory_id: String` is the primary identifier;
- `cve_id: Option<String>` is present only when a CVE alias is assigned;
- `package_name` and `package_type` bind the record to an ecosystem identity;
- `cvss_source: Option<String>` records score provenance;
- `exploit_available` changed from `bool` to `Option<bool>` so unknown is not reported as false.

Key persisted findings by ecosystem, normalized package name, and advisory identifier. Do not assume a CVE uniquely identifies one package record. Catalog browsing moved to the separate `AdvisoryCatalog` trait; its `get_by_advisory` method returns `Vec<Vulnerability>` and built-ins accept either the advisory ID or a CVE alias. Application injection implements only `VulnerabilityDatabase::check_package` and optional `metadata`.

`DatabaseMetadata` and `DatabaseCoverage` describe name, coverage, as-of date, and provenance. npm/Python results expose this through their `vulnerability_database` field and `AnalysisResult::vulnerability_database_metadata()`. Java returns `None`. Application databases should override the trait’s default metadata with accurate coverage and provenance.

## Scores and evidence

Parser validation, bounded evidence, deterministic ordering of library-owned data, and heuristic tuning can change:

- whether malformed data is rejected;
- the order of otherwise equivalent findings;
- which benign near-misses are suppressed;
- aggregate scores at bucket boundaries.

Do not snapshot only `total_score`. Migrate policies to inspect stable finding identifiers, source evidence, and vulnerability identifiers, then apply an application-owned decision rule.

`RiskCalculator::calculate` is now fallible and rejects non-finite or out-of-range input scores. Its raw supply-chain `f32` argument was replaced by `Option<SupplyChainSignal>` so analyzers attach capability-specific descriptions, evidence, and mitigations.

## Fallible pattern APIs

`PatternMatcher::scan` now returns `Result<Vec<MaliciousPattern>>` because input, path, and finding limits can fail:

```rust,ignore
// 0.1
let findings = matcher.scan(content, Some(path));

// 0.2
let findings = matcher.scan(content, Some(path))?;
```

`PatternDatabase::new`, `add_pattern`, and `import_json` are also fallible; `PatternDatabase::default()` was removed. Add/import validates the complete merged database atomically, so handle the error instead of assuming the mutation happened.

Custom `indicators` now perform case-sensitive literal matching. Empty indicators, file patterns, and regular expressions are rejected to prevent match-all definitions. Definition-time `evidence` must be empty because scan evidence is generated by the matcher. Rebaseline custom-rule tests before deployment.

## Persisted JSON

Do not assume 0.1 JSON can be deserialized as a 0.2 typed result. Public field names, enum representations, ordering, and bounded evidence behavior are compatibility-sensitive in this release.

Notable result-model changes include:

- the lowest `RiskLevel` variant was renamed from `Safe` to `Informational` so partial analysis is not labeled safe;
- `SecurityPosture::vulnerabilities_present` became `vulnerability_matches_present`;
- `malicious_code_detected` became `high_severity_pattern_matches_present`, which narrows its meaning;
- `actively_maintained`, `trusted_publisher`, and `security_practices_score` are now `Option` values and default to unknown (`None`);
- `AnalysisResult::quality_metrics()` now returns `Option<QualityMetrics>` and standard analyzers currently return `None`;
- npm/Python results include database metadata; Java includes an optional metadata field that is `None`;
- npm/Python results add `subject_vulnerabilities`; `AnalysisResult::subject_vulnerabilities()` exposes it through the unified API, while `vulnerabilities()` is the canonical deduplicated subject/dependency union and dependency summaries remain dependency-only;
- `DependencyAnalysis` includes `unresolved_requirements`;
- `Dependency::is_direct` and `is_dev` are now `Option<bool>` and `DependencyType::Unknown` represents requirements files that do not establish role/directness;
- `JavaPackage::is_signed` became `has_signature_block_entry`; unimplemented Android metadata and Java reflection/JNI/permission/API/certificate fields were removed instead of reporting observed-negative values;
- unpopulated Python format, classifier, project-URL, maintainer, and Python-requirement fields were removed from `PythonPackage`;
- public maps used for components, attributes, statistics, and package fields use deterministic `BTreeMap` ordering.

The aggregate advisory union is deduplicated and ordered by ecosystem, normalized package name, and advisory ID, including records returned by an application-provided database. Per-dependency raw records retain the implementation's order.

For durable storage:

1. store the producing crate version and ecosystem with every record;
2. retain the original package identity and evidence needed for review;
3. use an application-owned versioned envelope;
4. migrate or re-run 0.1 records instead of silently decoding them as 0.2.

`AnalysisResult::to_json` remains the unified export path. Use typed ecosystem analyzers when the consumer depends on ecosystem-specific fields.

## Feature flags

The no-op `offline` and `concurrent` features were removed. Remove them from dependency declarations:

```toml
# 0.1
threatflux-package-security = { version = "0.1", features = ["offline"] }

# 0.2: built-in analysis is always in memory and offline
threatflux-package-security = "0.2"
```

This built-in behavior is not a process-wide network sandbox. Injected `VulnerabilityDatabase` implementations run during npm/Python analysis and remain capable of arbitrary I/O and side effects.

## Migration checklist

- [ ] Use Rust 1.95 or newer.
- [ ] Replace `PackageSecurityAnalyzer::default()` with `new()?`.
- [ ] Remove unused `AnalysisOptions` code.
- [ ] Pass unpacked directories for npm and Python.
- [ ] Handle input-type, symlink, size, and archive-limit errors.
- [ ] Run analysis from an active Tokio runtime.
- [ ] Propagate errors from pattern scanning, pattern-database mutation, and risk calculation.
- [ ] Rebaseline heuristic findings, vulnerability matches, and score-based policies.
- [ ] Migrate vulnerability identity, database metadata, posture `Option` fields, and persisted JSON.
- [ ] Migrate subject/dependency result separation, dependency directness flags, Java signature naming, and removed dormant result fields.
- [ ] Remove `offline` and `concurrent` from dependency feature lists.
- [ ] Replace removed custom-path/updater calls with explicit npm/Python database injection where needed.
- [ ] Add timeout, retry, result-bound, provenance, and cancellation policy to injected databases.
- [ ] Run all targets, examples, and documentation with the locked dependency graph.
