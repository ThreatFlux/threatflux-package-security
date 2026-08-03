# Changelog

All notable changes to this project are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use [Semantic Versioning](https://semver.org/spec/v2.0.0.html) within the normal pre-1.0 compatibility rules.

## [Unreleased]

## [0.2.0] - 2026-08-03

### Added

- Explicit behavior, security-boundary, testing, migration, and release documentation.
- Focused examples for unified analysis and application-owned pattern sets.
- Reproducible CI, security, documentation, and trusted-publishing automation.
- npm/Python vulnerability-database injection with result-level coverage and provenance metadata.
- A minimal injection interface plus a separate read-only `AdvisoryCatalog` browsing surface.
- Explicit unresolved-requirement reporting and public metadata, archive, pattern, and evidence limits.
- Subject-package advisory matching with subject-only and canonical subject/dependency-union result accessors.
- Golden integrity tests for every embedded advisory record and shared-CVE lookup behavior.

### Changed

- Raised the minimum supported Rust version to 1.95 and adopted the Rust 2024 edition.
- Tightened package detection, parser validation, archive handling, error reporting, and deterministic result behavior.
- Made npm/Python subject identity validation ecosystem-aware and exact-version-only; advisory interval matching now follows SemVer/PEP 440 precedence for prereleases.
- Made Python metadata/dependency precedence deterministic, preserved legacy build-only `pyproject.toml` fallback, and replaced setup.py metadata guessing with conservative static-call parsing.
- Modeled unknown requirements-file role/directness with `DependencyType::Unknown` and `Option<bool>` flags.
- Deduplicated advisory matches by ecosystem/package/advisory identity without inflating dependency summaries or risk.
- Clarified that pattern matches, name similarity, vulnerability matches, and aggregate scores are review signals rather than security verdicts.
- Made package input and retained-result limits part of the documented analysis boundary.
- Removed unused dependencies so the built-in, in-memory analysis boundary is easier to audit.
- Changed vulnerability identity to a source-native advisory ID, optional CVE alias, ecosystem package identity, CVSS source, and tri-state exploit knowledge.
- Made pattern scanning, pattern-database construction/mutation, and risk calculation fallible.
- Activated custom case-sensitive literal indicators, rejected empty match-all definitions, and attached capability-specific supply-chain evidence through `SupplyChainSignal`.
- Removed high-severity defaults that mislabeled environment access, socket construction, imports, and generic startup identifiers as exfiltration, reverse shells, process execution, or persistence.
- Made unknown maintenance, publisher-trust, security-practices, and quality data explicit with `Option` values.
- Renamed the lowest risk bucket from `Safe` to `Informational` to avoid implying a security verdict.
- Exposed deterministic database coverage, as-of, and provenance metadata with npm/Python results; Java reports that no advisory database was consulted.
- Renamed Java signature presence to `has_signature_block_entry` and limited Java security output to implemented native-library inspection.

### Removed

- Claims of direct npm tarball and Python wheel/source-archive analysis where the implementation only supports unpacked directories.
- The no-op `offline` and `concurrent` feature flags and their unused dependencies; built-in analysis is offline without a feature switch.
- Misleading database-path constructors, mutable updater APIs, the placeholder updater module, unused `AnalysisOptions`, and panic-prone `Default` implementations for fallible analyzers/pattern databases.
- Dormant Java Android/reflection/JNI/permission/API/certificate fields and unpopulated Python format/classifier/project-URL/maintainer fields.
- The incomplete internal advisory version parser from the public API surface.
- Stale file-scanner templates, bootstrap scripts, and generic repository instructions.

### Security

- Hardened handling of untrusted paths, manifests, regular expressions, and ZIP-compatible Java archives.
- Added runtime guards, strict subject names/versions, bounded and escaped evidence, fail-closed static setup.py parsing, f-string expression inspection, and sanitized TOML parse failures.
- Documented archive-expansion, network, symlink, custom-pattern, application-state, and downstream-decision trust boundaries.
- Removed incorrect `event-stream`/CVE-2018-25032 and `ua-parser-js`/CVE-2021-25033 mappings from the bundled snapshot; those CVEs do not describe those packages.

## [0.1.0] - 2025-08-14

### Added

- Initial npm, Python, and Java analysis APIs.
- Bundled vulnerability records, pattern matching, risk scoring, and typosquatting heuristics.

[0.1.0]: https://github.com/ThreatFlux/threatflux-package-security/releases/tag/v0.1.0
