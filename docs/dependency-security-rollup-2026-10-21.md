# Stable dependency and security review

Reviewed 2026-10-21 against exact fetched main `9f 65f 1af 486e 44fd 737879920a 57a 65453bd 2066`.

Rust builds, release/docs/security workflows and current setup commands now use **1.99.1**, verified against the [official stable channel manifest](https://static.rust-lang.org/dist/channel-rust-stable.toml). Consumer MSRV remains **1.95.0** and the repository gate checks and tests that version separately. No API or package release version is manually changed.

Every direct/development crate was checked against the [crates.io sparse index](https://index.crates.io/config.json), excluding yanked/prerelease versions. ZIP advances from 8.6 to verified latest stable 9.0.5, beyond open PR 17's 9.0.2. TOML's published version is 1.1.8+spec-1.1.0; its requirement uses 1.1.8 because Cargo ignores SemVer build metadata for resolution. Cargo.lock retains the published version and compatible transitive stable updates.

| Crate | Verified stable release |
| --- | --- |
| anyhow | 1.0.104 |
| async-trait | 0.1.92 |
| chrono | 0.4.45 |
| pep 440_rs | 0.7.3 |
| regex | 1.13.1 |
| serde | 1.0.229 |
| serde_json | 1.0.154 |
| strsim | 0.11.1 |
| tempfile | 3.27.0 |
| tokio | 1.54.0 |
| toml | 1.1.8+spec-1.1.0 |
| zip | 9.0.5 |

Actions were checked against authoritative GitHub stable tags and advanced where needed, including shared ThreatFlux release workflow 0.7.8, install-action 2.87.29, upload-artifact 7.0.2 and download-artifact 8.0.2. Cargo tool pins are verified stable: llvm-cov 0.9.1, audit 0.22.2 and deny 0.20.2. The project is an offline-first library without a shipped Docker runtime or required native libraries; a container migration would not address this artifact.

Paginated GitHub inventory returned **zero open code-scanning alerts** and three dependency PRs: 17 (ZIP), 18 (Cargo group), 19 (Actions). No finding is invented or dismissed, and zero open alerts is not a proof of complete scanner coverage. All three dependency changes are included in the replacement and closed only after it is pushed and reviewable. Existing nondependency PRs are preserved. No Jira tickets or advisory ignores are introduced.

Validation uses the complete repository `make ci`: format/check/Clippy, full tests and doctests, compiled Markdown, consumer-MSRV check and tests, rustdoc, examples, audit/deny and verified package. Existing Java archive regressions cover unsafe paths, symlinks, nested signatures, bounded ZIP-directory preflight and ZIP 64 rejection, making them material for the ZIP major upgrade. ZIP 9 returns a fallible archive entry name; the Java reader now propagates that error with context and continues to enforce its existing size and path restrictions. Final results are recorded in the PR.

Executed result: the complete `CARGO_BUILD_JOBS=2 make ci` gate passed, including 41 unit tests, 24 integration tests and 3 doctests on stable and again on the consumer MSRV where applicable; Markdown examples compiled, strict Clippy/rustdoc passed, RustSec audit returned no warnings or vulnerabilities, cargo-deny passed all categories, and Cargo packaged and verified the crate. Four existing illustrative Markdown blocks remain ignored by their authors. `actionlint` and `git diff --check` also passed. There is no repo hook installation target.
