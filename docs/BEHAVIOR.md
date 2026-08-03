# Behavior and Guarantees

This document defines the intended 0.2 analysis contract. When it differs from an example or marketing description, this document is authoritative for behavior; Rust API signatures and configured limits remain authoritative for exact types and values.

## Analysis lifecycle

`PackageSecurityAnalyzer::analyze` must be polled from an active Tokio runtime. It returns an error rather than panicking when no runtime is active. It then:

1. validates and classifies the caller-provided path;
2. routes it to the npm, Python, or Java analyzer;
3. parses supported metadata without executing package code;
4. derives dependency, pattern, vulnerability, and package-name signals supported for that ecosystem;
5. calculates a triage score and returns a complete result.

Unsupported, unreadable, malformed, symlinked, or over-limit input returns an error. The API does not convert a failed analysis into an empty or `Informational` result.

Error messages are escaped where they include caller-controlled paths or content, but their concrete type and wording are not a stable classification API. Callers must not parse `Display` strings for policy decisions.

The unified analyzer rejects a directory that advertises more than one supported ecosystem instead of silently choosing one and suppressing the other analyzer. Call an ecosystem-specific analyzer when mixed metadata is intentional.

## Supported inputs

### npm

The input must be a directory whose direct `package.json` child is a regular file. The subject name must use the supported lowercase npm package-name grammar and its version must be an exact SemVer version. Analysis covers package metadata; declared runtime, development, peer, and optional dependencies; lifecycle-script text; subject and dependency advisory matches; and package-name similarity. Pattern matching receives the concatenated script names and bodies, not the complete manifest. A same-name `optionalDependencies` declaration overrides `dependencies`, following npm semantics; development and peer roles remain distinct declarations.

The analyzer does not install dependencies, execute scripts, consult a registry, expand npm tarballs, or resolve a lockfile/transitive graph.

### Python

The input must be a directory with a supported direct metadata file: `pyproject.toml`, `setup.cfg`, or `setup.py`. Metadata selection is deterministic. A valid `pyproject.toml` containing `[project]` wins. A valid build-only `pyproject.toml` without `[project]` falls through to `setup.cfg`, then `setup.py`; malformed TOML is an error rather than a reason to fall back. Subject names must use the supported PEP 503 distribution-name grammar and versions must be exact PEP 440 versions.

Dependencies come from `[project].dependencies` whenever that key is present, including when it is an empty array. Otherwise, `requirements.txt` is the fallback. Dependencies declared only in `setup.cfg` or `setup.py` are not resolved in 0.2. PEP 621 entries are known direct runtime declarations (`is_direct: Some(true)`, `is_dev: Some(false)`). A standalone requirements file does not establish role or directness, so those entries use `DependencyType::Unknown` and `None` for both flags.

When `setup.py` is present, its bounded text is inspected for setup-operation and pattern signals even if another file supplied package metadata. It is never imported or executed. If it supplies subject metadata, exactly one unambiguous `setup()` call with simple static string `name` and `version` values is required; dynamic expressions fail closed. The lexical scan masks comments and ordinary string contents while retaining executable f-string replacement expressions. This is deliberately a bounded heuristic, not a Python AST or execution model.

The analyzer does not build a distribution, import modules, invoke packaging tools, expand wheels/source archives, resolve environment markers, or resolve a transitive environment. A requirement with an environment marker remains in `unresolved_requirements` and is not passed to a vulnerability database: without a caller-supplied target environment, stripping the marker would turn a conditional declaration into an unconditional match.

Python packaging permits dynamic metadata. A value that requires execution is outside this analyzer’s static contract.

### Java

The input must be a regular `.jar`, `.war`, `.ear`, `.apk`, or `.aar` ZIP-compatible file. The analyzer inspects entries in place and never extracts them. It reads bounded manifest metadata and notes recognized signature-related and native-library entries.

It does not decompile bytecode, verify JAR/APK signatures or certificate chains, parse Android manifests, resolve Maven/Gradle dependencies, establish publisher trust, or treat manifest values as executable-code patterns. `has_signature_block_entry` means a recognized JAR-style signature-block filename was present, not that a signature is valid. `JavaSecurityAnalysis` reports only the implemented native-library-entry signal.

Java results contain empty dependency, vulnerability, and malicious-pattern lists, and `vulnerability_database_metadata()` returns `None`. There is no Java database-injection constructor because archive filenames and manifest attributes do not establish authoritative Maven coordinates.

Java archives are rejected when public built-in limits are exceeded, when member paths are unsafe, when an entry is encrypted, or when the container is malformed. Limits cover the archive file, encoded central directory, entry count, entry-name length, individual advertised uncompressed size, aggregate advertised uncompressed size, and manifest bytes retained. The per-entry and aggregate expansion checks rely on sizes advertised by the ZIP container; the selected manifest read is independently bounded by bytes actually read. Other entries are not generally decompressed.

## Filesystem semantics

- The input path itself and required metadata children must have supported regular-file/directory types.
- Manifest-like child files are rejected when they are symlinks. This avoids silently crossing the caller-selected project root.
- The library does not provide a durable filesystem sandbox. The caller remains responsible for path authorization, mount boundaries, concurrent path replacement, permissions, and platform-specific special files.
- Analysis reads input but does not modify the package directory or extract archive members.

## Vulnerability matching

The standard npm and Python analyzers contain bounded, embedded advisory snapshots for selected package/advisory pairs. They are available offline, report `DatabaseCoverage::CuratedPartial` with an as-of date and provenance, and cannot be updated. Java analysis does not consult a snapshot.

A built-in match means a record associated with the ecosystem and normalized package name matched either the analyzed subject's exact version or an exact dependency version. Ranges, wildcards, tags, URLs, marked Python requirements, and malformed requirements are not treated as confirmed built-in matches and may be listed in `DependencyAnalysis::unresolved_requirements`. Embedded `affected_versions` values model advisory introduced/fixed intervals. They include prereleases by version precedence and are not npm or PEP 440 dependency-specifier prerelease filters. A match does not mean:

- the database is comprehensive or current;
- a range declaration resolves to the affected version in the caller’s environment;
- the vulnerable code path is reachable;
- an empty result proves absence of vulnerabilities.

`Vulnerability::advisory_id` is the source-native identifier; `cve_id` is an optional alias. Records also carry package identity and optional CVSS-source/exploit knowledge. The optional `AdvisoryCatalog::get_by_advisory` browsing API can match an advisory identifier or CVE alias and returns a vector because one alias can correspond to multiple package records. Analyzer injection requires only the smaller `VulnerabilityDatabase` lookup/metadata interface.

`subject_vulnerabilities()` returns subject-only matches. `vulnerabilities()` is the deterministic, deduplicated union of subject and dependency matches. `DependencyAnalysis::vulnerability_summary` remains dependency-only. Identity is `(ecosystem, normalized package, advisory ID)`.

Confirm material findings against the authoritative advisory and the actual resolved dependency graph. Malformed or unsupported version syntax must not silently become a positive assertion of safety. Consumers should display `vulnerability_database_metadata()` with results so partial or application-defined coverage is not lost.

## Pattern matching

Built-in patterns inspect npm lifecycle scripts and `setup.py` text. Java manifest values are not scanned. Matches carry an identifier, category, severity, and bounded evidence. Severity describes the rule’s triage priority, not proof of intent or exploitability.

`PatternMatcher::with_patterns` replaces the built-in set with caller-provided patterns. Indicators are non-empty, case-sensitive literal matches; regular expressions and file patterns have their documented semantics. Empty matchers and definition-time `evidence` are rejected because empty values match everything and evidence is populated only from a scan. Invalid or over-limit definitions fail matcher construction. `scan` returns `Result<Vec<_>>` and fails for over-limit input, path text, or detected-pattern count.

`PatternDatabase::new`, `add_pattern`, and `import_json` are fallible. Add/import validates the complete merged database before replacement, so a failed validation leaves the existing database unchanged. Custom patterns run in process and are trusted configuration; the caller owns their quality, runtime characteristics, and data-handling effects.

Patterns do not recursively scan every file in a package. The ecosystem sections above define the content actually presented to the matcher.

## Package-name similarity

Typosquatting detection compares a normalized candidate with a finite built-in set and common mutation shapes. It does not query registry popularity, ownership, download counts, namespace provenance, or publication history.

A similarity match can be legitimate; a non-match can still be deceptive. Use it to prioritize manual identity and provenance checks.

## Dependency analysis

`DependencyAnalysis` summarizes only declarations parsed from supported metadata. Unless explicitly populated, fields for transitive dependencies, resolved versions, licenses, update status, and graph depth are not inferred. Zero or empty placeholder fields mean “not observed by this analysis,” not necessarily “none exist.” npm and Python requirements that cannot be reduced to the built-in snapshot's exact-version form are retained in `unresolved_requirements`; Python requirements with environment markers are also retained there because no target environment is evaluated. Application-provided databases still receive parsed unmarked ranges and own their package/version semantics.

## Risk scoring

The total score is a deterministic, bounded triage aggregation of available components. Analyzer-specific supply-chain signals carry typed score, description, evidence, and mitigation data, so native libraries, install hooks, custom setup commands, and explicit execution primitives are not mislabeled as one another. The level thresholds are:

| Score              | Level           |
| ------------------ | --------------- |
| Less than 20       | `Informational` |
| 20 to less than 40 | `Low`           |
| 40 to less than 60 | `Medium`        |
| 60 to less than 80 | `High`          |
| 80 to 100          | `Critical`      |

The score is not a calibrated probability. `Informational` is the lowest triage bucket, not a safety guarantee. Consumers should make decisions from the component findings and evidence, with an explicit local policy, rather than treating the number as a universal allow/block threshold.

`SecurityPosture` distinguishes observed matches from unknown facts. Maintenance status, trusted-publisher status, and security-practices score are `Option` values and are currently unknown (`None`) for standard analyzers. Signature-entry presence never changes `trusted_publisher` to `Some(true)`. `AnalysisResult::quality_metrics()` likewise returns `None` unless an analyzer computes real metrics.

## Ordering and serialization

Library-owned, semantically unordered output is normalized to a deterministic order before it is exposed or serialized. The aggregate `vulnerabilities()` union is deduplicated and ordered canonically by ecosystem, normalized package name, and advisory ID, including records returned by an application-provided database. Per-dependency raw records remain as returned by that implementation. Pattern identifiers and serialized enum/field names are compatibility-sensitive within a compatible release line. See the [migration guide](MIGRATING_TO_0.2.md) before consuming persisted 0.1 JSON.

The trait-object result returned by the unified analyzer can be converted with `AnalysisResult::to_json`. Applications that require a typed ecosystem-specific result should use that ecosystem analyzer directly.

## Resource bounds

Library limits are independent ceilings, not a global heap-byte budget. Several legal inputs or retained fields can multiply into a larger allocation. The caller should additionally bound source file size, process memory, concurrency, elapsed time, and total work per tenant.

The constants are public in `threatflux_package_security::limits`:

| Boundary                                       |          0.2 limit |
| ---------------------------------------------- | -----------------: |
| One npm/Python project metadata file           |              4 MiB |
| Java archive file                              | 256 MiB compressed |
| Encoded ZIP central directory                  |             64 MiB |
| Java archive entries                           |             20,000 |
| One archive entry name                         |        4 KiB UTF-8 |
| One entry’s advertised uncompressed size       |             32 MiB |
| Aggregate advertised uncompressed archive size |            512 MiB |
| Java manifest content                          |              1 MiB |
| Retained Java manifest attributes              |              4,096 |
| Direct dependency declarations                 |             20,000 |
| One package metadata scalar                    |       64 KiB UTF-8 |
| One package metadata collection                |             20,000 |
| Pattern scan input or imported pattern JSON    |        4 MiB UTF-8 |
| Pattern scan file-path text                    |        4 KiB UTF-8 |
| Custom pattern definitions                     |              1,024 |
| One pattern identifier                         |          256 bytes |
| One pattern display name                       |        1 KiB UTF-8 |
| One pattern description                        |       16 KiB UTF-8 |
| Indicator or file-pattern values per pattern   |                256 |
| One indicator or file-pattern value            |        4 KiB UTF-8 |
| Aggregate indicator and file-pattern values    |             16,384 |
| Aggregate custom pattern-definition data       |              8 MiB |
| Regular expressions per pattern                |                 64 |
| Regular expressions per matcher                |                256 |
| One regular expression                         |        4 KiB UTF-8 |
| Aggregate custom regular-expression text       |      256 KiB UTF-8 |
| One compiled regular-expression program        |            256 KiB |
| Evidence strings per matched pattern           |                 64 |
| Matched patterns per scan                      |                256 |
| Aggregate evidence strings per scan            |              1,024 |

Over-limit input and pattern definitions are errors. Evidence retention stops at the per-pattern and aggregate evidence ceilings; exceeding the matched-pattern ceiling is an error. Limits are independent security behavior, not a global heap-byte budget, and do not cap records returned by an injected vulnerability database. Raising any limit increases worst-case resource use and should receive focused review.

## Network and database behavior

Built-in npm/Python databases are always in memory. Their construction, lookup, and analysis paths do not perform network requests or read/write advisory caches. Java analysis does not use a vulnerability database.

`NpmAnalyzer::with_database`, `PythonAnalyzer::with_database`, and `PackageSecurityAnalyzer::with_vulnerability_databases` accept injected implementations. `PackageSecurityAnalyzer::from_analyzers` composes configured analyzers. After input parsing and validation, npm/Python await `check_package` sequentially for parsed, unmarked dependency declarations and the exact subject package. They request synchronous `metadata` only when assembling a successful result. Metadata must still be cheap, nonblocking, and side-effect free. The injection trait has no mutable update operation.

The library provides no timeout, retry, network sandbox, returned-record cap, output validation, or transaction around an injected implementation. A database error fails the entire analysis. The implementation owns authentication, redirects, response validation, package/version semantics, freshness, provenance, persistence, side effects, cancellation, and all resource limits. Its metadata and records become part of the result and risk calculation.

## Concurrency and cancellation

Analyzers are safe to share only where their public trait bounds permit. Async analysis may perform blocking archive work internally; run untrusted high-volume workloads behind application-level concurrency and time limits.

Dropping an async future is not a transactional rollback guarantee for injected-database I/O. Enforce timeouts inside that implementation or around the complete analysis future; an outer async timeout cannot preempt blocking work inside synchronous `metadata`. Built-in analysis does not mutate the input package.
