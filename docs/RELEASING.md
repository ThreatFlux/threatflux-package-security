# Release Process

Releases are produced by GitHub Actions from an immutable version tag and published to crates.io with trusted publishing. No long-lived registry token is involved.

## One-time repository setup

Repository administrators must configure:

1. a protected `crates-io` environment, limited to `v*` tags, for the publish job;
2. a crates.io trusted publisher bound to this repository, the `release.yml` workflow, and the `crates-io` environment;
3. protected `main` and `v*` tags with required CI and security checks;
4. least-privilege default Actions permissions and no workflow approval of pull requests;
5. GitHub Pages with “GitHub Actions” as its source if documentation deployment is enabled.

Every publication uses crates.io trusted publishing. Only a real release runs the publish job in the
`crates-io` environment; there, `rust-lang/crates-io-auth-action` exchanges the job's GitHub OIDC
identity for a short-lived token, and the action revokes that token when the job ends. The workflow
reads no registry secret and has no token fallback, so a failed exchange fails the release. Do not
add a crates.io API token as a repository, environment, or organization secret for this workflow.

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

The version must not already exist on crates.io when a routine release begins. The tagged workflow may observe an existing version when a prior run published successfully but failed later. It must then verify the locally rebuilt package against the canonical crates.io checksum before continuing.

## Publishing credentials

Versions 0.2.0 and 0.2.1 were published with a registry token. That fallback has been removed now that the crate exists on crates.io and its trusted publisher is configured. Never pass a crates.io token on a command line, store it in shell history, commit it, or add it as a long-lived secret. If the local rebuild does not match the canonical crates.io archive, stop and investigate; do not attach a different artifact under the same version.

## Rehearse a release

Both release workflows accept a `dry_run` dispatch input that never tags, releases, publishes, or
uploads anything:

```bash
gh workflow run auto-release.yml -f dry_run=true
gh workflow run release.yml -f dry_run=true -f version=0.2.2
```

The auto-release dry run logs the version and tag the next release would take and the files its
version-bump commit would rewrite. It analyzes only after CI and Security have passed on the
dispatched commit; otherwise the release job is skipped. Like a real run, it fails if the
`Cargo.toml` version is lower than the latest release tag. The `release.yml` dry run
builds the dispatch ref (add `--ref <branch>` to rehearse another branch), needs no tag, and stages
the same `Cargo.toml`/`Cargo.lock` version bump the automated release commit makes in a local,
unpushed commit. It then runs the full test matrix and the publish-job gates that apply before a tag
exists, through `cargo package` and `cargo publish --dry-run --locked`. It skips the
`Verify annotated tag is on main` and `Recheck immutable release tag` checks, the `crates-io`
environment, crates.io authentication and upload, the artifact upload, and the GitHub release. It
fails if the version is already on crates.io. A dispatch without `dry_run` rejects `version`.

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
- the crates.io state is valid: unpublished for a new release, or an exact package-checksum match for a recovery rerun;
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
