# Security Policy

## Supported versions

Security fixes are currently applied to `main`. Version 0.2 has not yet been published to crates.io, so there is no supported published release line.

| Version                      | Supported |
| ---------------------------- | --------- |
| `main` (0.2 pre-release)     | Yes       |
| Existing 0.1 repository tags | No        |

Because the crate is pre-1.0, a security fix may include compatibility changes when preserving the old behavior would be unsafe.

## Report a vulnerability

Do not open a public issue for a suspected vulnerability.

Use [GitHub private vulnerability reporting](https://github.com/ThreatFlux/threatflux-package-security/security/advisories/new). If that channel is unavailable, email `security@threatflux.ai` with the repository name in the subject.

Include only what is safe and necessary:

- affected version or commit;
- affected parser, analyzer, database, or workflow;
- a minimal reproduction using synthetic input;
- realistic impact and required attacker capabilities;
- suggested mitigations, if known;
- whether disclosure is coordinated with another project.

Do not send live credentials, private packages, or active malware. Arrange a secure transfer channel with the maintainers if a sensitive artifact is essential.

## Security model

Package inputs, manifests, dependency strings, archive members, vulnerability data, and custom patterns must be treated as untrusted. The library’s findings are heuristic evidence; they are not an authorization decision, malware verdict, or proof that an input is safe.

### Filesystem and archive boundary

- The analyzer reads caller-selected paths. The caller must authorize those paths and decide how symlinks, mount boundaries, races, and special files are handled.
- ZIP-compatible Java archives can consume significant CPU, memory, and decompressed bytes. Enforce caller-side file-size and execution limits in addition to library limits.
- Merely observing a signature-related archive entry does not verify a cryptographic signature or publisher identity.
- The library does not intentionally execute package code or lifecycle scripts. Do not add execution to an analysis pipeline without a separate, disposable sandbox.

### Network and vulnerability-data boundary

- Standard npm/Python analysis uses small bundled snapshots and does not require a network request. Java analysis does not consult an advisory database.
- Bundled records are deliberately partial and age over time. Confirm results against authoritative ecosystem and advisory sources.
- `NpmAnalyzer::with_database`, `PythonAnalyzer::with_database`, and the unified injection constructor accept application-provided database implementations. Their synchronous `metadata` and async `check_package` methods run in process during analysis; `check_package` calls are sequential.
- The analyzer supplies no timeout, retry, network isolation, returned-record cap, or transactional boundary around an injected database. It trusts returned records and metadata; an error aborts the analysis.
- An injected implementation owns TLS policy, authentication, redirects, response and result-size limits, schema validation, freshness, rollback resistance, persistence, provenance, and version semantics.

### Application-owned database state

- Built-in databases do not read or write a cache and expose no mutable update operation.
- If an injected database persists state, that mutable state is not a trust anchor. Use a private directory, restrictive permissions, atomic updates, and integrity metadata.
- Do not share writable advisory state between mutually untrusted users or privilege levels.

### Pattern and callback boundary

- Application-provided regular expressions and injected database implementations are trusted in-process code/data.
- Compile custom patterns before accepting work, bound the content scanned, and review expression changes for pathological runtime or match amplification.
- An injected `VulnerabilityDatabase` can perform arbitrary I/O or side effects from `metadata` and `check_package`. Input parsing/validation precedes database calls, and `metadata` is requested while assembling a successful result, but it must remain cheap, nonblocking, and side-effect free. Bound and validate database output before returning it to the analyzer. Enforce async timeouts inside the implementation or around the complete analysis future; an outer timeout cannot preempt synchronous blocking work.
- Cancellation is cooperative. Dropping an analysis future does not guarantee rollback of external I/O already started by an injected database.

### Decision boundary

False positives and false negatives are expected. `Informational` is only the lowest score bucket and does not imply safety. Human review and defense-in-depth remain necessary before installing, publishing, allowing, blocking, or deleting a package.

## In-scope examples

- path traversal or unintended file access caused by package-controlled data;
- archive expansion that bypasses documented limits;
- parser panic, memory exhaustion, or disproportionate CPU consumption on a bounded input;
- incorrect version matching that materially hides a known affected version;
- unsafe behavior in a built-in advisory lookup or database-injection boundary;
- sensitive information exposed in errors, logs, serialized results, or CI artifacts;
- release workflow compromise or provenance failure.

General false-positive/false-negative tuning without a security boundary impact can be reported through the public issue tracker using synthetic evidence.

## Disclosure

Maintainers will coordinate validation, remediation, release, and public disclosure with the reporter. Do not publish exploit details until a fix or agreed mitigation is available. Credit is offered when requested and appropriate.
