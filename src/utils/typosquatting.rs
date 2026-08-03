//! Deterministic, ecosystem-scoped package-name similarity heuristics.
//!
//! These checks are signals for review, not proof of malicious intent.

use std::collections::BTreeSet;
use strsim::levenshtein;

/// Package namespace used to select the comparison corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageEcosystem {
    Npm,
    Python,
    Java,
    All,
}

/// Typosquatting detector backed by a small built-in comparison corpus.
pub struct TyposquattingDetector {
    popular_packages: BTreeSet<String>,
    ecosystem: PackageEcosystem,
}

impl TyposquattingDetector {
    /// Create a detector using all built-in ecosystems.
    ///
    /// Prefer [`Self::for_ecosystem`] when the package ecosystem is known, to
    /// avoid cross-ecosystem false positives.
    pub fn new() -> Self {
        Self::for_ecosystem(PackageEcosystem::All)
    }

    /// Create a detector using only one ecosystem's comparison corpus.
    pub fn for_ecosystem(ecosystem: PackageEcosystem) -> Self {
        let packages: &[&str] = match ecosystem {
            PackageEcosystem::Npm => NPM_POPULAR_PACKAGES,
            PackageEcosystem::Python => PYTHON_POPULAR_PACKAGES,
            PackageEcosystem::Java => JAVA_POPULAR_PACKAGES,
            PackageEcosystem::All => &[],
        };
        let mut popular_packages = packages
            .iter()
            .map(|package| normalize_for_ecosystem(package, ecosystem))
            .collect::<BTreeSet<_>>();
        if ecosystem == PackageEcosystem::All {
            popular_packages.extend(
                NPM_POPULAR_PACKAGES
                    .iter()
                    .chain(PYTHON_POPULAR_PACKAGES)
                    .chain(JAVA_POPULAR_PACKAGES)
                    .map(|package| (*package).to_string()),
            );
        }
        Self {
            popular_packages,
            ecosystem,
        }
    }

    /// Check whether a package name is suspiciously close to the built-in corpus.
    pub fn is_typosquatting(&self, package_name: &str) -> bool {
        let package_name = normalize_for_ecosystem(package_name, self.ecosystem);
        if package_name.is_empty() || self.popular_packages.contains(&package_name) {
            return false;
        }

        self.suspicious_affix_base(&package_name).is_some()
            || self.popular_packages.iter().any(|popular| {
                let distance = levenshtein(&package_name, popular);
                distance > 0 && distance <= similarity_threshold(popular.chars().count())
            })
    }

    /// Find similar corpus names, ordered by edit distance and then name.
    pub fn find_similar(&self, package_name: &str) -> Vec<String> {
        let package_name = normalize_for_ecosystem(package_name, self.ecosystem);
        let mut similar = self
            .popular_packages
            .iter()
            .filter_map(|popular| {
                let distance = levenshtein(&package_name, popular);
                (distance > 0 && distance <= 3).then(|| (distance, popular.clone()))
            })
            .collect::<Vec<_>>();
        if let Some(base) = self.suspicious_affix_base(&package_name)
            && !similar.iter().any(|(_, candidate)| candidate == base)
        {
            similar.push((levenshtein(&package_name, base), base.to_string()));
        }
        similar.sort();
        similar.into_iter().map(|(_, name)| name).collect()
    }

    fn suspicious_affix_base<'a>(&'a self, name: &'a str) -> Option<&'a str> {
        const SUFFIXES: &[&str] = &[
            "-dev",
            "-test",
            "-beta",
            "-alpha",
            "-rc",
            "-snapshot",
            "-official",
            "-real",
            "-new",
        ];
        const PREFIXES: &[&str] = &["fake-", "new-", "real-", "official-"];

        SUFFIXES
            .iter()
            .find_map(|suffix| name.strip_suffix(suffix))
            .or_else(|| PREFIXES.iter().find_map(|prefix| name.strip_prefix(prefix)))
            .filter(|base| self.popular_packages.contains(*base))
    }
}

fn normalize_for_ecosystem(name: &str, ecosystem: PackageEcosystem) -> String {
    match ecosystem {
        PackageEcosystem::Python => crate::utils::package_name::python(name),
        PackageEcosystem::Npm => crate::utils::package_name::npm(name),
        PackageEcosystem::Java => crate::utils::package_name::java(name),
        PackageEcosystem::All => name.trim().to_lowercase(),
    }
}

fn similarity_threshold(character_count: usize) -> usize {
    if character_count >= 7 { 2 } else { 1 }
}

impl Default for TyposquattingDetector {
    fn default() -> Self {
        Self::new()
    }
}

const NPM_POPULAR_PACKAGES: &[&str] = &[
    "react",
    "express",
    "axios",
    "lodash",
    "moment",
    "webpack",
    "typescript",
    "vue",
    "angular",
    "jquery",
    "bootstrap",
    "eslint",
    "babel-core",
    "jest",
    "mocha",
    "chai",
    "gulp",
    "grunt",
    "nodemon",
    "prettier",
    "commander",
];

const PYTHON_POPULAR_PACKAGES: &[&str] = &[
    "numpy",
    "pandas",
    "requests",
    "flask",
    "django",
    "tensorflow",
    "matplotlib",
    "scipy",
    "scikit-learn",
    "pytest",
    "pillow",
    "beautifulsoup4",
    "selenium",
    "pytorch",
    "keras",
    "sqlalchemy",
    "celery",
    "scrapy",
    "opencv-python",
];

const JAVA_POPULAR_PACKAGES: &[&str] = &[
    "spring-core",
    "spring-boot",
    "junit",
    "log4j",
    "commons-lang",
    "guava",
    "jackson-core",
    "gson",
    "okhttp",
    "retrofit",
    "hibernate-core",
    "mockito",
    "slf4j-api",
    "logback-classic",
    "apache-commons",
    "jetty",
    "tomcat",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_popular_names_are_not_flagged() {
        let detector = TyposquattingDetector::for_ecosystem(PackageEcosystem::Npm);
        assert!(!detector.is_typosquatting("React"));
    }

    #[test]
    fn results_are_ecosystem_scoped_and_deterministic() {
        let npm = TyposquattingDetector::for_ecosystem(PackageEcosystem::Npm);
        let python = TyposquattingDetector::for_ecosystem(PackageEcosystem::Python);
        assert!(npm.is_typosquatting("loadash"));
        assert!(!python.is_typosquatting("loadash"));
        assert_eq!(npm.find_similar("loadash"), vec!["lodash"]);
        assert!(!python.is_typosquatting("scikit_learn"));
    }

    #[test]
    fn suspicious_affix_returns_the_comparison_target() {
        let detector = TyposquattingDetector::for_ecosystem(PackageEcosystem::Npm);
        assert!(detector.is_typosquatting("official-react"));
        assert_eq!(detector.find_similar("official-react"), vec!["react"]);
    }
}
