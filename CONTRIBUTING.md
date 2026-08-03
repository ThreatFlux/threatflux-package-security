# Contributing

Thank you for improving ThreatFlux Package Security. Changes should preserve the distinction between a review signal and a verified security conclusion.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

- Search [existing issues](https://github.com/ThreatFlux/threatflux-package-security/issues) before opening a new one.
- Use a GitHub issue for usage questions and design exploration that the documentation does not answer.
- Open an issue before a large API, data-model, parser, scoring, or dependency change.
- Report suspected vulnerabilities privately according to [SECURITY.md](SECURITY.md), not in a public issue.

## Development setup

Install the pinned toolchain and required components:

```bash
rustup show
rustup component add rustfmt clippy llvm-tools-preview
cargo fetch --locked
```

See [DEVELOPMENT.md](DEVELOPMENT.md) for the architecture and [TESTING.md](TESTING.md) for the complete validation matrix.

## Make a change

1. Fork the repository and branch from `main`.
2. Add the smallest coherent change and focused regression tests.
3. Keep behavior deterministic: avoid filesystem-order, hash-order, clock, and network dependencies in tests and serialized results.
4. Bound all work derived from untrusted package input. Include adversarial tests for parser and archive changes.
5. Update public rustdoc, examples, behavior documentation, and the changelog when observable behavior changes.
6. Run the local validation commands before opening a pull request.

Do not add real malware, credentials, access tokens, private packages, or proprietary advisory data to fixtures. Synthetic strings should be unmistakably non-routable and non-secret (for example, `example.invalid`).

## Validation

At minimum:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps --locked
```

Run the security and package checks described in [TESTING.md](TESTING.md) for dependency, release, parser, archive, or workflow changes.

## Pull requests

A useful pull request includes:

- the problem and intended behavior;
- user-visible and compatibility impact;
- security and resource-consumption implications;
- tests that fail without the change;
- documentation for changed public behavior;
- the exact validation commands run.

Maintainers may request changes to preserve compatibility, bounded resource use, deterministic output, or evidence quality. Keep unrelated cleanup in a separate pull request.

## Review expectations

Security-sensitive changes need explicit review of:

- untrusted file and archive handling;
- path traversal and symlink behavior;
- input, allocation, recursion, and output limits;
- regular-expression construction and runtime behavior;
- advisory version matching and ecosystem semantics;
- application-owned database-state integrity and network access;
- score or severity changes that affect downstream policy.

## Licensing

By contributing, you agree that your contribution is licensed under the repository’s [MIT License](LICENSE).
