//! Utility modules

pub(crate) mod input;
pub(crate) mod package_name;
pub mod pattern_matcher;
pub mod typosquatting;
pub(crate) mod version_parser;

pub(crate) fn require_tokio_runtime() -> anyhow::Result<()> {
    tokio::runtime::Handle::try_current()
        .map(|_| ())
        .map_err(|_| anyhow::anyhow!("package analysis requires an active Tokio runtime"))
}
