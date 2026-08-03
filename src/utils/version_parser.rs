//! Small, deterministic version parser used by the embedded advisory snapshot.
//!
//! This is intentionally not a complete npm or Maven range parser. Python
//! candidate versions use `pep440_rs`; advisory matching only runs when the
//! analyzed dependency supplies an exact version. Unresolved ranges are not
//! reported as confirmed vulnerabilities.

use anyhow::{Result, anyhow, bail};
use std::cmp::Ordering;

/// Parsed version with SemVer-compatible precedence for its supported subset.
#[derive(Debug, Clone)]
pub struct Version {
    major: u32,
    minor: u32,
    patch: u32,
    pre_release: Option<String>,
}

impl Version {
    /// Parse `major`, `major.minor`, or `major.minor.patch`, with optional
    /// prerelease and build identifiers. A leading `v` is accepted.
    pub fn parse(version: &str) -> Result<Self> {
        let version = version.trim();
        let version = version
            .strip_prefix('v')
            .or_else(|| version.strip_prefix('V'))
            .unwrap_or(version);
        if version.is_empty() || version.bytes().any(|byte| byte.is_ascii_whitespace()) {
            bail!("invalid version: {version:?}");
        }

        let (version, build) = split_once_nonempty(version, '+')?;
        let (version, pre_release) = split_once_nonempty(version, '-')?;
        let parts: Vec<_> = version.split('.').collect();
        if parts.is_empty() || parts.len() > 3 || parts.iter().any(|part| part.is_empty()) {
            bail!("invalid version core: {version:?}");
        }

        let parse_component = |index: usize| -> Result<u32> {
            parts
                .get(index)
                .copied()
                .unwrap_or("0")
                .parse()
                .map_err(|_| anyhow!("invalid numeric version component in {version:?}"))
        };

        if let Some(value) = pre_release.as_deref() {
            validate_identifiers(value, "prerelease")?;
        }
        if let Some(value) = build.as_deref() {
            validate_identifiers(value, "build")?;
        }

        Ok(Self {
            major: parse_component(0)?,
            minor: parse_component(1)?,
            patch: parse_component(2)?,
            pre_release,
        })
    }

    /// Parse a dependency requirement only when it identifies one exact
    /// version. Range operators, wildcards, URLs, tags, and compound specs are
    /// deliberately rejected because they do not identify the installed build.
    pub fn parse_exact_requirement(requirement: &str) -> Result<Self> {
        let mut requirement = requirement.trim();
        if let Some(stripped) = requirement.strip_prefix("===") {
            requirement = stripped.trim();
        } else if let Some(stripped) = requirement.strip_prefix("==") {
            requirement = stripped.trim();
        } else if let Some(stripped) = requirement.strip_prefix('=') {
            requirement = stripped.trim();
        }

        let core = requirement.split(['-', '+']).next().unwrap_or(requirement);
        let has_wildcard_component = core
            .split('.')
            .any(|component| matches!(component, "x" | "X" | "*"));
        if requirement.is_empty()
            || requirement.contains(|character: char| {
                matches!(
                    character,
                    '<' | '>' | '^' | '~' | '*' | ',' | '|' | ' ' | '\t'
                )
            })
            || has_wildcard_component
            || requirement.contains("://")
            || requirement.starts_with("git+")
        {
            bail!("dependency requirement is not an exact version");
        }

        Self::parse(requirement)
    }

    /// Check whether this exact version satisfies the supported advisory syntax.
    ///
    /// Supported expressions are exact versions, `<`, `<=`, `>`, `>=`, `=`,
    /// inclusive `a to b` ranges, comma-separated conjunctions, and `||`-joined
    /// alternatives.
    pub fn satisfies(&self, specification: &str) -> bool {
        specification.split("||").any(|alternative| {
            let alternative = alternative.trim();
            if alternative.is_empty() {
                return false;
            }

            alternative
                .split(',')
                .all(|clause| self.satisfies_clause(clause.trim()))
        })
    }

    fn satisfies_clause(&self, clause: &str) -> bool {
        if let Some((minimum, maximum)) = clause.split_once(" to ") {
            return Version::parse(minimum.trim())
                .ok()
                .zip(Version::parse(maximum.trim()).ok())
                .is_some_and(|(minimum, maximum)| self >= &minimum && self <= &maximum);
        }

        for (operator, predicate) in [
            (">=", OrderingPredicate::GreaterOrEqual),
            ("<=", OrderingPredicate::LessOrEqual),
            ("==", OrderingPredicate::Equal),
            (">", OrderingPredicate::Greater),
            ("<", OrderingPredicate::Less),
            ("=", OrderingPredicate::Equal),
        ] {
            if let Some(value) = clause.strip_prefix(operator) {
                return Version::parse(value.trim())
                    .ok()
                    .is_some_and(|other| predicate.matches(self.cmp(&other)));
            }
        }

        Version::parse(clause).is_ok_and(|other| self == &other)
    }
}

fn split_once_nonempty(value: &str, delimiter: char) -> Result<(&str, Option<String>)> {
    let Some((left, right)) = value.split_once(delimiter) else {
        return Ok((value, None));
    };
    if left.is_empty() || right.is_empty() || right.contains(delimiter) {
        bail!("invalid version identifier in {value:?}");
    }
    Ok((left, Some(right.to_string())))
}

fn validate_identifiers(value: &str, kind: &str) -> Result<()> {
    if value.split('.').any(|identifier| {
        identifier.is_empty()
            || !identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        bail!("invalid {kind} version identifier: {value:?}");
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum OrderingPredicate {
    Less,
    LessOrEqual,
    Equal,
    GreaterOrEqual,
    Greater,
}

impl OrderingPredicate {
    fn matches(self, ordering: Ordering) -> bool {
        match self {
            Self::Less => ordering == Ordering::Less,
            Self::LessOrEqual => ordering != Ordering::Greater,
            Self::Equal => ordering == Ordering::Equal,
            Self::GreaterOrEqual => ordering != Ordering::Less,
            Self::Greater => ordering == Ordering::Greater,
        }
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version {}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.major
            .cmp(&other.major)
            .then_with(|| self.minor.cmp(&other.minor))
            .then_with(|| self.patch.cmp(&other.patch))
            .then_with(|| compare_prerelease(&self.pre_release, &other.pre_release))
    }
}

fn compare_prerelease(left: &Option<String>, right: &Option<String>) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(left), Some(right)) => {
            for (left, right) in left.split('.').zip(right.split('.')) {
                let ordering = match (left.parse::<u64>(), right.parse::<u64>()) {
                    (Ok(left), Ok(right)) => left.cmp(&right),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => left.cmp(right),
                };
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
            left.split('.').count().cmp(&right.split('.').count())
        }
    }
}

/// Return whether an exact dependency requirement matches one of the advisory
/// expressions. Non-exact dependency requirements return `false`.
pub(crate) fn exact_requirement_is_affected(
    requirement: &str,
    affected_versions: &[String],
) -> bool {
    Version::parse_exact_requirement(requirement).is_ok_and(|version| {
        affected_versions
            .iter()
            .any(|affected| version.satisfies(affected))
    })
}

/// Apply npm's exact-version boundary before consulting the embedded snapshot.
/// Bare partial versions are npm ranges, not exact installed versions.
/// Advisory introduced/fixed intervals include prereleases according to SemVer
/// precedence; they are not npm dependency-range prerelease filters.
pub(crate) fn exact_npm_requirement_is_affected(
    requirement: &str,
    affected_versions: &[String],
) -> bool {
    let Ok(version) = parse_exact_npm_requirement(requirement) else {
        return false;
    };

    affected_versions
        .iter()
        .any(|affected| version.satisfies(affected))
}

/// Match an exact PEP 440 version against embedded advisory intervals.
pub(crate) fn exact_python_requirement_is_affected(
    requirement: &str,
    affected_versions: &[String],
) -> bool {
    let Ok(version) = parse_exact_python_requirement(requirement) else {
        return false;
    };
    affected_versions.iter().any(|affected| {
        affected.split("||").any(|alternative| {
            alternative
                .split(',')
                .all(|raw_clause| python_version_satisfies_clause(&version, raw_clause.trim()))
        })
    })
}

/// Parse the exact subset accepted for npm advisory matching.
pub(crate) fn parse_exact_npm_requirement(requirement: &str) -> Result<Version> {
    let requirement = requirement.trim();
    let stripped = if let Some(stripped) = requirement.strip_prefix('=') {
        if stripped.starts_with('=') {
            bail!("npm exact versions accept at most one '=' prefix");
        }
        stripped.trim_start()
    } else {
        requirement
    };
    let stripped = stripped
        .strip_prefix('v')
        .or_else(|| stripped.strip_prefix('V'))
        .unwrap_or(stripped);
    let core = stripped.split(['-', '+']).next().unwrap_or(stripped);
    let components = core.split('.').collect::<Vec<_>>();
    if components.len() != 3
        || components
            .iter()
            .any(|component| component.len() > 1 && component.starts_with('0'))
    {
        bail!("npm dependency requirement is not an exact SemVer version");
    }

    let version = Version::parse_exact_requirement(requirement)?;
    if version.pre_release.as_deref().is_some_and(|prerelease| {
        prerelease.split('.').any(|identifier| {
            identifier.len() > 1
                && identifier.starts_with('0')
                && identifier.bytes().all(|byte| byte.is_ascii_digit())
        })
    }) {
        bail!("npm prerelease contains a numeric identifier with a leading zero");
    }
    Ok(version)
}

/// Parse a package.json subject version, excluding requirement-only prefixes.
pub(crate) fn parse_npm_subject_version(version: &str) -> Result<Version> {
    if version != version.trim()
        || version
            .bytes()
            .next()
            .is_some_and(|byte| matches!(byte, b'=' | b'v' | b'V'))
    {
        bail!("npm subject version is not canonical SemVer");
    }
    parse_exact_npm_requirement(version)
}

/// Parse an exact PEP 440 version accepted for Python advisory matching.
pub(crate) fn parse_exact_python_requirement(requirement: &str) -> Result<pep440_rs::Version> {
    use std::str::FromStr;

    let trimmed = requirement.trim();
    let version = if let Some(version) = trimmed.strip_prefix("===") {
        version.trim()
    } else if let Some(version) = trimmed.strip_prefix("==") {
        version.trim()
    } else if trimmed.starts_with('=') {
        bail!("single '=' is not a valid Python version operator");
    } else {
        trimmed
    };
    if version.is_empty()
        || version.contains(|character: char| {
            matches!(
                character,
                '<' | '>' | '^' | '~' | '*' | ',' | '|' | ' ' | '\t'
            )
        })
        || version.contains("://")
        || version.starts_with("git+")
    {
        bail!("Python dependency requirement is not an exact version");
    }
    pep440_rs::Version::from_str(version).map_err(Into::into)
}

/// Parse a Python subject version, excluding requirement-specifier operators.
pub(crate) fn parse_python_subject_version(version: &str) -> Result<pep440_rs::Version> {
    if version != version.trim() || version.starts_with('=') {
        bail!("Python subject version is not a PEP 440 version");
    }
    parse_exact_python_requirement(version)
}

fn python_version_satisfies_clause(version: &pep440_rs::Version, clause: &str) -> bool {
    use std::str::FromStr;

    for (operator, predicate) in [
        (">=", OrderingPredicate::GreaterOrEqual),
        ("<=", OrderingPredicate::LessOrEqual),
        ("==", OrderingPredicate::Equal),
        (">", OrderingPredicate::Greater),
        ("<", OrderingPredicate::Less),
        ("=", OrderingPredicate::Equal),
    ] {
        if let Some(value) = clause.strip_prefix(operator) {
            return pep440_rs::Version::from_str(value.trim())
                .ok()
                .is_some_and(|other| predicate.matches(version.cmp(&other)));
        }
    }

    pep440_rs::Version::from_str(clause).is_ok_and(|other| version == &other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_partial_versions_and_ignores_build_for_precedence() {
        let version = Version::parse("v1.2-beta.1+linux").expect("valid version");
        assert_eq!((version.major, version.minor, version.patch), (1, 2, 0));
        assert_eq!(version.pre_release.as_deref(), Some("beta.1"));
        assert_eq!(
            version,
            Version::parse("1.2.0-beta.1+windows").expect("valid version")
        );
    }

    #[test]
    fn rejects_malformed_versions() {
        for invalid in ["", "1.2.3.4", "1..2", "1.2.3-", "1.2.3+a+b", "1. 2"] {
            assert!(Version::parse(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn compares_prerelease_identifiers_semantically() {
        let beta_two = Version::parse("1.0.0-beta.2").expect("valid version");
        let beta_ten = Version::parse("1.0.0-beta.10").expect("valid version");
        let release = Version::parse("1.0.0").expect("valid version");
        assert!(beta_two < beta_ten);
        assert!(beta_ten < release);
    }

    #[test]
    fn evaluates_supported_advisory_ranges_in_operator_order() {
        let version = Version::parse("1.2.3").expect("valid version");
        assert!(version.satisfies(">= 1.2.3, < 2.0.0"));
        assert!(version.satisfies("1.0.0 to 1.2.3"));
        assert!(version.satisfies("< 1.0.0 || == 1.2.3"));
        assert!(!version.satisfies("> 1.2.3"));
        assert!(!version.satisfies("<= 1.2.2"));
        assert!(!version.satisfies("nonsense"));
    }

    #[test]
    fn only_exact_requirements_are_confirmed_affected() {
        let affected = vec!["< 4.17.12".to_string()];
        assert!(exact_requirement_is_affected("4.17.10", &affected));
        assert!(exact_requirement_is_affected("== 4.17.10", &affected));
        assert!(!exact_requirement_is_affected("^4.17.10", &affected));
        assert!(!exact_requirement_is_affected("*", &affected));
        assert!(!exact_requirement_is_affected("4.17.21", &affected));
        assert!(Version::parse_exact_requirement("1.0.0-linux").is_ok());
        assert!(!exact_npm_requirement_is_affected("4", &affected));
        assert!(!exact_npm_requirement_is_affected("4.17", &affected));
        assert!(!exact_npm_requirement_is_affected("04.17.10", &affected));
        assert!(!exact_npm_requirement_is_affected(
            "4.17.10-beta.01",
            &affected
        ));
        assert!(exact_npm_requirement_is_affected(
            "4.17.12-beta.0",
            &affected
        ));
        assert!(exact_python_requirement_is_affected(
            "==4.17.12-beta.0",
            &affected
        ));
        assert!(!exact_python_requirement_is_affected("=4.17.10", &affected));
        assert!(!exact_npm_requirement_is_affected("==4.17.10", &affected));
        assert!(!exact_npm_requirement_is_affected("===4.17.10", &affected));
    }

    #[test]
    fn advisory_intervals_include_prereleases_before_the_fixed_version() {
        let affected = vec!["< 1.0.0".to_string()];
        assert!(exact_npm_requirement_is_affected("1.0.0-alpha", &affected));
        assert!(exact_npm_requirement_is_affected("1.0.0-beta.2", &affected));
        assert!(exact_python_requirement_is_affected("1.0rc1", &affected));
        assert!(!exact_npm_requirement_is_affected("1.0.0", &affected));
        assert!(!exact_python_requirement_is_affected("1.0", &affected));
    }
}
