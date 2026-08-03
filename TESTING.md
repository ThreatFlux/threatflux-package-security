# Testing

The test strategy validates public behavior, parser boundaries, deterministic output, dependency policy, and the packaged crate. Security analyzers need both positive detections and false-positive resistance.

## Fast local loop

```bash
cargo fmt --all -- --check
cargo test --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
```

Use a focused test while iterating:

```bash
cargo test --locked test_name -- --exact
cargo test --test analysis_boundaries --locked
```

## Full validation

Run before requesting review:

```bash
cargo +1.97.1 fmt --all -- --check
cargo +1.97.1 check --all-targets --all-features --locked
cargo +1.97.1 clippy --all-targets --all-features --locked -- -D warnings
cargo +1.97.1 test --all-targets --all-features --locked
cargo +1.97.1 test --doc --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo +1.97.1 doc --all-features --no-deps --locked
make markdown
cargo +1.95.0 check --all-targets --all-features --locked
cargo +1.95.0 test --all-targets --all-features --locked
cargo audit --deny warnings
cargo deny check
cargo +1.97.1 package --allow-dirty --locked
cargo +1.97.1 publish --dry-run --allow-dirty --locked
```

The explicit `+1.95.0` commands bypass the directory’s pinned stable override. A plain `cargo` command in this repository uses Rust 1.97.1 and does not validate the MSRV.

## Required coverage by change type

| Change                      | Required evidence                                                                                                                                         |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Manifest parser             | Valid input, missing fields, malformed syntax, oversized input, symlink rejection, and non-UTF-8 behavior                                                 |
| Java archive handling       | Entry-count, compressed-size, per-entry and aggregate advertised uncompressed size, long-name, encrypted-entry, unsafe-path, and malformed-ZIP boundaries |
| Pattern or name heuristic   | True positive, benign near miss, deterministic evidence, case behavior, and output cap                                                                    |
| Version/advisory matching   | Below, at, within, and above every interval boundary plus malformed and ecosystem-specific versions                                                       |
| Risk scoring                | Every threshold boundary, saturation, non-finite input rejection, and stable component mapping                                                            |
| Serialization               | Round trip and deterministic ordering for library-owned public result data                                                                                |
| Custom database integration | Offline built-in baseline, metadata propagation, errors, implementation-enforced result/time bounds, cancellation, and application-owned I/O behavior     |
| Public API                  | Rustdoc/example compilation and migration documentation                                                                                                   |

## Fixture policy

- Use temporary directories; never depend on a developer’s home or OS cache.
- Keep fixtures synthetic, minimal, and reviewable.
- Use `example.invalid` for URLs and obvious placeholders for credentials.
- Do not include live malware, secrets, private packages, copyrighted package archives, or exploit payloads.
- Construct archive fixtures in tests and assert their intended compressed and expanded shapes.
- Tests must not call public package registries or advisory services.

## False-positive and false-negative tests

Each heuristic change should include:

1. a high-signal sample that should match;
2. a benign near miss that should not match;
3. an unrelated ordinary package sample;
4. an assertion on identifier, severity, and bounded evidence—not only the total score.

An aggregate risk-score assertion alone can hide a detector regression because several components contribute to the same score.

## Determinism

Run order-sensitive tests repeatedly when changing collections or concurrency:

```bash
for _ in 1 2 3 4 5; do
  cargo test --all-targets --all-features --locked
done
```

Never repair flaky behavior by adding sleeps or weakening assertions. Remove the nondeterministic input or define a stable ordering contract.

## Coverage

When `cargo-llvm-cov` is installed:

```bash
cargo llvm-cov --all-features --all-targets --locked --lcov --output-path lcov.info
```

Coverage is a navigation aid, not a security guarantee. Prioritize boundary conditions and invariant checks over a percentage target.

## Package inspection

Review the exact published surface:

```bash
cargo package --list --allow-dirty --locked
```

The package must not include caches, credentials, local reports, generated documentation, target artifacts, or real package samples.
