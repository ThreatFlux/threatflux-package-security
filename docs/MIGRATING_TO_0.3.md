# Migrating advisory timestamps to 0.3

`Vulnerability::published_date`, `Vulnerability::updated_date`, and
`DatabaseStatistics::last_updated` now take `Option<AdvisoryTimestamp>`.
Import `threatflux_package_security::AdvisoryTimestamp` when constructing those
records in Rust.

```rust
use threatflux_package_security::AdvisoryTimestamp;

let published: AdvisoryTimestamp = "2020-12-31T23:30:00.123Z".parse()?;
let from_parts = AdvisoryTimestamp::from_unix_timestamp(1_609_457_400, 123_000_000)?;
assert_eq!(published, from_parts);
# Ok::<(), threatflux_package_security::ParseAdvisoryTimestampError>(())
```

During migration, pass an existing UTC value's `timestamp()` and
`timestamp_subsec_nanos()` to `AdvisoryTimestamp::from_unix_timestamp`.
Fractions at or above one billion nanoseconds preserve a leap second in the
preceding whole Unix second. Use `year()` for the UTC calendar year.

Existing serialized records can be read as-is. The fields still accept
`null` and timestamp strings with UTC offsets, preserve leap seconds and
nanosecond precision, and serialize in UTC using `Z`. Years outside
0000–9999 retain their explicit sign. The UTC range remains -262143-01-01
through +262142-12-31.
