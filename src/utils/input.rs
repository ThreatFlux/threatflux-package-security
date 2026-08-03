//! Bounded input helpers for package metadata stored in directories.

use anyhow::{Context, Result, bail};
use std::path::{Component, Path};
use tokio::io::AsyncReadExt;

/// Read one regular, non-symlink project file through an opened handle.
///
/// `relative_path` must be a normal relative path. The size is checked both from
/// the opened handle's metadata and while reading. On Unix, the pre-open and
/// opened file identities are compared to detect a path swap between checks.
pub(crate) async fn read_project_file(
    project_root: &Path,
    relative_path: &Path,
    max_bytes: u64,
) -> Result<String> {
    let root_metadata = tokio::fs::symlink_metadata(project_root)
        .await
        .with_context(|| format!("failed to inspect project root {project_root:?}"))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        bail!("project root must be a non-symlink directory");
    }
    if relative_path.is_absolute()
        || relative_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("project metadata path must be a normal relative path");
    }

    let path = project_root.join(relative_path);
    let link_metadata = tokio::fs::symlink_metadata(&path)
        .await
        .with_context(|| format!("failed to inspect {path:?}"))?;
    if link_metadata.file_type().is_symlink() {
        bail!("refusing symlinked project metadata: {path:?}");
    }
    if !link_metadata.is_file() {
        bail!("project metadata is not a regular file: {path:?}");
    }

    let file = tokio::fs::File::open(&path)
        .await
        .with_context(|| format!("failed to open {path:?}"))?;
    let metadata = file
        .metadata()
        .await
        .with_context(|| format!("failed to inspect opened file {path:?}"))?;
    if !metadata.is_file() {
        bail!("project metadata is not a regular file: {path:?}");
    }
    if !same_file_identity(&link_metadata, &metadata) {
        bail!("project metadata changed while it was being opened: {path:?}");
    }
    if metadata.len() > max_bytes {
        bail!("project metadata exceeds the {max_bytes}-byte limit: {path:?}");
    }

    let capacity = usize::try_from(metadata.len()).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .await
        .with_context(|| format!("failed to read {path:?}"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        bail!("project metadata exceeds the {max_bytes}-byte limit: {path:?}");
    }

    String::from_utf8(bytes).with_context(|| format!("{path:?} is not valid UTF-8"))
}

/// Return whether a root and one direct child are non-symlink directory/file
/// objects. This is a cheap capability probe; analysis repeats the checks while
/// opening the input.
pub(crate) fn has_regular_project_file(project_root: &Path, relative_path: &Path) -> bool {
    std::fs::symlink_metadata(project_root).is_ok_and(|metadata| {
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && std::fs::symlink_metadata(project_root.join(relative_path))
                .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
    })
}

#[cfg(unix)]
fn same_file_identity(before: &std::fs::Metadata, opened: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    before.dev() == opened.dev() && before.ino() == opened.ino()
}

#[cfg(not(unix))]
fn same_file_identity(before: &std::fs::Metadata, opened: &std::fs::Metadata) -> bool {
    before.file_type() == opened.file_type() && before.len() == opened.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[tokio::test]
    async fn reads_regular_bounded_utf8_file() {
        let directory = tempfile::tempdir().expect("temporary directory");
        std::fs::write(directory.path().join("package.json"), "{}").expect("write metadata");

        assert_eq!(
            read_project_file(directory.path(), Path::new("package.json"), 2)
                .await
                .expect("read metadata"),
            "{}"
        );
        assert!(
            read_project_file(directory.path(), Path::new("package.json"), 1)
                .await
                .is_err()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_symlinked_project_metadata() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("target.json");
        std::fs::write(&target, "{}").expect("write target");
        symlink(&target, directory.path().join("package.json")).expect("create symlink");

        let error = read_project_file(directory.path(), Path::new("package.json"), 100)
            .await
            .expect_err("symlink must be rejected");
        assert!(error.to_string().contains("symlinked"));
    }
}
