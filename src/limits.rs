//! Resource limits applied while inspecting untrusted package metadata.

/// Maximum size of a project metadata file read from a directory (4 MiB).
pub const MAX_PROJECT_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Maximum compressed size of a Java archive accepted for analysis (256 MiB).
pub const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;

/// Maximum number of entries accepted in a Java archive.
pub const MAX_ARCHIVE_ENTRIES: usize = 20_000;

/// Maximum encoded ZIP central-directory size accepted before parsing (64 MiB).
pub const MAX_ARCHIVE_DIRECTORY_BYTES: u64 = 64 * 1024 * 1024;

/// Maximum advertised uncompressed size of one Java archive entry (32 MiB).
pub const MAX_ARCHIVE_ENTRY_BYTES: u64 = 32 * 1024 * 1024;

/// Maximum aggregate advertised uncompressed size of a Java archive (512 MiB).
pub const MAX_ARCHIVE_TOTAL_UNCOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;

/// Maximum UTF-8 byte length of one archive entry name.
pub const MAX_ARCHIVE_ENTRY_NAME_BYTES: usize = 4 * 1024;

/// Maximum uncompressed size of a Java manifest (1 MiB).
pub const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

/// Maximum number of attributes retained from a Java manifest main section.
pub const MAX_MANIFEST_ATTRIBUTES: usize = 4_096;

/// Maximum number of direct dependencies accepted from one manifest.
pub const MAX_DIRECT_DEPENDENCIES: usize = 20_000;

/// Maximum content size accepted by a heuristic-pattern scan (4 MiB).
pub const MAX_PATTERN_INPUT_BYTES: usize = 4 * 1024 * 1024;

/// Maximum number of custom pattern definitions accepted by one matcher.
pub const MAX_CUSTOM_PATTERNS: usize = 1_024;

/// Maximum number of regular expressions accepted by one pattern definition.
pub const MAX_REGEXES_PER_PATTERN: usize = 64;

/// Maximum aggregate number of regular expressions accepted by one matcher.
pub const MAX_TOTAL_REGEXES: usize = 256;

/// Maximum UTF-8 byte length of a custom regular expression.
pub const MAX_REGEX_BYTES: usize = 4 * 1024;

/// Maximum aggregate UTF-8 byte length of custom regular expressions.
pub const MAX_TOTAL_REGEX_BYTES: usize = 256 * 1024;

/// Maximum compiled size accepted for one regex program (256 KiB).
pub const MAX_REGEX_COMPILED_BYTES: usize = 256 * 1024;

/// Maximum number of evidence strings returned for one detected pattern.
pub const MAX_EVIDENCE_PER_PATTERN: usize = 64;

/// Maximum number of detected patterns returned by one scan.
pub const MAX_DETECTED_PATTERNS: usize = 256;

/// Maximum aggregate number of evidence strings returned by one scan.
pub const MAX_TOTAL_EVIDENCE: usize = 1_024;

/// Maximum UTF-8 byte length of a pattern identifier.
pub const MAX_PATTERN_ID_BYTES: usize = 256;

/// Maximum UTF-8 byte length of a pattern display name.
pub const MAX_PATTERN_NAME_BYTES: usize = 1_024;

/// Maximum UTF-8 byte length of a pattern description.
pub const MAX_PATTERN_DESCRIPTION_BYTES: usize = 16 * 1_024;

/// Maximum number of indicator or file-pattern values on one pattern.
pub const MAX_PATTERN_LIST_ITEMS: usize = 256;

/// Maximum UTF-8 byte length of one indicator or file-pattern value.
pub const MAX_PATTERN_LIST_VALUE_BYTES: usize = 4 * 1024;

/// Maximum aggregate number of indicator/file-pattern list values.
pub const MAX_TOTAL_PATTERN_LIST_ITEMS: usize = 16_384;

/// Maximum aggregate bytes retained by one pattern definition collection.
pub const MAX_TOTAL_PATTERN_DEFINITION_BYTES: usize = 8 * 1024 * 1024;

/// Maximum UTF-8 byte length of one package metadata scalar.
pub const MAX_METADATA_FIELD_BYTES: usize = 64 * 1024;

/// Maximum number of values retained in one package metadata collection.
pub const MAX_METADATA_LIST_ITEMS: usize = 20_000;
