# Pull request

## Summary

<!-- What problem does this solve, and what observable behavior changes? -->

## Related issue

<!-- Use “Closes #123” when appropriate. -->

## Change type

- [ ] Bug fix
- [ ] Feature
- [ ] Breaking change
- [ ] Security hardening
- [ ] Performance or resource-bound change
- [ ] Documentation, CI, or maintenance

## Security and compatibility

<!-- Cover untrusted input, archive/path handling, network/cache effects, execution boundaries, false positives/negatives, public API, serialized data, scoring, MSRV, and feature flags as applicable. -->

## Validation

<!-- List exact commands and focused cases, including benign near misses for heuristic changes. -->

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets --all-features --locked -- -D warnings`
- [ ] `cargo test --all-targets --all-features --locked`
- [ ] Documentation and migration notes are updated where needed.
- [ ] Package contents were inspected for release-affecting changes.

## Reviewer focus

<!-- Call out code paths, invariants, or tradeoffs that deserve particular scrutiny. -->
