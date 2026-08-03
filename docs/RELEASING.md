# Release Process

After the crate exists on crates.io, releases are produced by GitHub Actions from an immutable version tag. The initial publication has a separately controlled bootstrap because crates.io trusted publishing cannot create a new crate.

## One-time repository setup

Repository administrators must configure:

1. a protected `crates-io` environment for the publish job;
2. after the bootstrap release, a crates.io trusted publisher bound to this repository and release workflow;
3. protected `main` and `v*` tags with required CI and security checks;
4. least-privilege default Actions permissions and no workflow approval of pull requests;
5. GitHub Pages with “GitHub Actions” as its source if documentation deployment is enabled.

Routine releases use crates.io OIDC. The first publication may fall back to the organization-managed
`CARGO_REGISTRY_TOKEN` secret because crates.io cannot issue an OIDC token for a crate that does not
exist yet. Do not copy that credential into the repository or expose it in workflow output; configure
the trusted publisher after bootstrap and remove the fallback when the release train is complete.

## Prepare the release

1. Start from an up-to-date `main` with a clean worktree.
2. Choose the version using SemVer and the crate’s pre-1.0 compatibility policy.
3. Update `Cargo.toml`, `Cargo.lock`, and `CHANGELOG.md` together.
4. Replace the release’s `Unreleased` date and ensure every changelog link targets an existing tag or release.
5. Update migration and behavior documentation for compatibility or semantic changes.
6. Run the full matrix in [TESTING.md](../TESTING.md).
7. Inspect the exact package contents and generated `.crate` archive.

Useful checks include:

```bash
cargo metadata --locked --no-deps --format-version 1
cargo package --list --locked
cargo package --locked
cargo publish --dry-run --locked
```

The version must not already exist on crates.io when a routine release begins. The tagged workflow may observe an existing version during the first-release bootstrap or when a prior run published successfully but failed later. In either case, it must verify the locally rebuilt package against the canonical crates.io checksum before continuing.

## Bootstrap the first crates.io release

Only repository owners and crates.io owners should perform the bootstrap. Complete review and every preparation check on the exact `main` commit first.

1. Provide a crates.io token scoped to publishing a new crate through the organization-managed
   `CARGO_REGISTRY_TOKEN` Actions secret.
2. From a clean checkout of the reviewed `main` release commit, rebuild and inspect the package.
3. Create and push the matching immutable annotated tag on that same commit.
4. Let the release workflow prefer OIDC and fall back to the bootstrap secret for the first publication.
5. Verify the canonical crates.io archive checksum and confirm the published version.
6. Confirm that the GitHub release contains the canonical archive, checksum, and package-content list.
7. Configure the crates.io trusted publisher for subsequent releases.
8. Revoke the bootstrap token or remove its release-workflow access after every crate in the
   coordinated bootstrap train has migrated to trusted publishing.

Never pass the token on a command line, store it in shell history, commit it, or add it as a long-lived repository secret. If the local rebuild does not match the canonical crates.io archive, stop and investigate; do not attach a different artifact under the same version.

## Tag and publish subsequent releases

Create an annotated tag whose name exactly matches the package version:

```bash
git tag -s v0.2.0 -m "threatflux-package-security 0.2.0"
git push origin v0.2.0
```

If signed tags are not available under the project’s key policy, use an annotated tag and preserve the GitHub audit trail. Never reuse or move a published release tag.

The release workflow must independently verify:

- the tag is a valid `vMAJOR.MINOR.PATCH` release tag;
- the tagged commit is on `main`;
- the tag and `Cargo.toml` versions agree;
- the crates.io state is valid: unpublished for a new release, or an exact package-checksum match for a bootstrap/recovery rerun;
- formatting, linting, tests, docs, security policy, and package dry-run pass;
- the published artifact is the same generated `.crate` archive that was verified;
- the GitHub release contains the canonical `.crate`, its checksum, and the package-content list;
- GitHub records build provenance for the canonical `.crate` through an artifact attestation.

## Verify after publication

After the workflow succeeds:

```bash
cargo search threatflux-package-security --limit 1
cargo info threatflux-package-security@0.2.0
```

Also verify:

- the crates.io version and docs.rs build;
- the GitHub release notes, canonical archive, checksum, and package-content list;
- the artifact attestation recorded by GitHub for that archive;
- a clean consumer can compile the documented quick start;
- release and documentation workflows are green.

## Failure recovery

### Failure before crates.io publication

Fix the release commit, choose a new tag if the old tag was pushed, and rerun through the normal workflow. Delete an unpublished erroneous tag only when repository policy allows it and the exact remote target has been verified.

### Crates.io succeeded, later steps failed

A crates.io version is immutable. Do not move the tag, rebuild a different archive with the same version, or republish.

Use the immutable release tag and the canonical crates.io archive/checksum to finish the GitHub release manually or through a narrowly scoped recovery workflow. If the published crate itself is defective, yank it when appropriate and publish a new patch version. Yanking is not deletion and should include an explanation.

The normal workflow supports rerunning the same immutable tag after a publish-stage partial failure. It rebuilds the package, requires the checksum to match crates.io, downloads and re-attests the canonical archive, and creates or updates the GitHub release without republishing. Existing release assets are replaced only with the checksum-verified canonical artifacts.

### Compromised or incorrect release

Stop the workflow, preserve logs and provenance, rotate any affected credentials, and follow [SECURITY.md](../SECURITY.md). Publish a corrective version and advisory; never conceal the incident by rewriting tags or assets.
