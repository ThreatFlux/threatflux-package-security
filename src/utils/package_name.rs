//! Ecosystem-specific package-name normalization.

/// Normalize an npm package name for lookup.
pub(crate) fn npm(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

/// Normalize a Python distribution name according to PEP 503.
pub(crate) fn python(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    let mut in_separator = false;
    for character in name.trim().chars() {
        if matches!(character, '-' | '_' | '.') {
            if !in_separator {
                normalized.push('-');
                in_separator = true;
            }
        } else {
            normalized.extend(character.to_lowercase());
            in_separator = false;
        }
    }
    normalized
}

/// Normalize a Maven-style artifact identifier for lookup.
pub(crate) fn java(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_names_follow_pep_503_equivalence() {
        assert_eq!(python("Friendly_Bard...Test"), "friendly-bard-test");
    }
}
