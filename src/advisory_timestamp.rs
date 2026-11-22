use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::{fmt, str::FromStr, sync::LazyLock};
use time::{Date, Month, OffsetDateTime, Time};

const MIN_YEAR: i32 = -262_143;
const MAX_YEAR: i32 = 262_142;
const NANOS_PER_SECOND: u32 = 1_000_000_000;

// Keep the relaxed timestamp input accepted by the 0.2 wire format.
static TIMESTAMP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?x)\A\s*([+-][0-9]+|[0-9]{1,4})\s*-\s*([0-9]{1,2})\s*-\s*([0-9]{1,2})",
        r"[Tt\x20]\s*([0-9]{1,2})\s*:\s*([0-9]{1,2})\s*:\s*([0-9]{1,2})",
        r"(?:\.([0-9]+))?\s*(?:(?i:z|utc)|([+−-])([0-9]{2})[:\s]*([0-9]{2}))\s*\z",
    ))
    .expect("valid advisory timestamp pattern")
});

/// A UTC advisory timestamp with nanosecond precision, including leap seconds.
///
/// Its text and Serde representation is an RFC 3339 UTC string with signed
/// expanded years outside 0000–9999. The supported UTC years are
/// -262143 through +262142, inclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AdvisoryTimestamp {
    instant: OffsetDateTime,
    nanosecond: u32,
}

/// A malformed or out-of-range advisory timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseAdvisoryTimestampError;

impl fmt::Display for ParseAdvisoryTimestampError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid advisory timestamp")
    }
}

impl std::error::Error for ParseAdvisoryTimestampError {}

impl AdvisoryTimestamp {
    /// Construct from whole Unix seconds and fractional nanoseconds.
    ///
    /// A leap second is represented by 1,000,000,000–1,999,999,999 nanoseconds
    /// in a whole Unix second ending in :59. Returns an error for an
    /// out-of-range timestamp or fractional part.
    pub fn from_unix_timestamp(
        seconds: i64,
        nanosecond: u32,
    ) -> Result<Self, ParseAdvisoryTimestampError> {
        let instant = OffsetDateTime::from_unix_timestamp(seconds)
            .map_err(|_| ParseAdvisoryTimestampError)?;
        if !(MIN_YEAR..=MAX_YEAR).contains(&instant.year())
            || nanosecond >= 2 * NANOS_PER_SECOND
            || (nanosecond >= NANOS_PER_SECOND && instant.second() != 59)
        {
            return Err(ParseAdvisoryTimestampError);
        }
        Ok(Self {
            instant,
            nanosecond,
        })
    }

    /// Return the whole Unix seconds. A leap second shares its preceding :59.
    pub fn unix_timestamp(self) -> i64 {
        self.instant.unix_timestamp()
    }

    /// Return fractional nanoseconds, including the extra second for a leap second.
    pub fn subsec_nanosecond(self) -> u32 {
        self.nanosecond
    }

    /// Return the calendar year in UTC.
    pub fn year(self) -> i32 {
        self.instant.year()
    }
}

impl FromStr for AdvisoryTimestamp {
    type Err = ParseAdvisoryTimestampError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parts = TIMESTAMP
            .captures(value)
            .ok_or(ParseAdvisoryTimestampError)?;
        let parse_small = |index: usize| {
            parts[index]
                .parse::<u8>()
                .map_err(|_| ParseAdvisoryTimestampError)
        };
        let year = parts[1].parse().map_err(|_| ParseAdvisoryTimestampError)?;
        let month = Month::try_from(parse_small(2)?).map_err(|_| ParseAdvisoryTimestampError)?;
        let date = Date::from_calendar_date(year, month, parse_small(3)?)
            .map_err(|_| ParseAdvisoryTimestampError)?;
        let second = parse_small(6)?;
        let leap_second = second == 60;
        let time = Time::from_hms(
            parse_small(4)?,
            parse_small(5)?,
            second - u8::from(leap_second),
        )
        .map_err(|_| ParseAdvisoryTimestampError)?;
        let mut nanosecond = u32::from(leap_second) * NANOS_PER_SECOND;
        if let Some(fraction) = parts.get(7) {
            let digits = fraction.as_str();
            let kept = &digits[..digits.len().min(9)];
            nanosecond += kept
                .parse::<u32>()
                .map_err(|_| ParseAdvisoryTimestampError)?
                * 10_u32.pow(9 - kept.len() as u32);
        }
        let mut offset_seconds = 0;
        if let Some(sign) = parts.get(8) {
            let hours = parse_small(9)?;
            let minutes = parse_small(10)?;
            if hours >= 24 || minutes >= 60 {
                return Err(ParseAdvisoryTimestampError);
            }
            offset_seconds = i64::from(hours) * 3_600 + i64::from(minutes) * 60;
            if sign.as_str() != "+" {
                offset_seconds = -offset_seconds;
            }
        }
        Self::from_unix_timestamp(
            date.with_time(time).assume_utc().unix_timestamp() - offset_seconds,
            nanosecond,
        )
    }
}

impl fmt::Display for AdvisoryTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (year, month, day) = self.instant.to_calendar_date();
        let (hour, minute, mut second) = self.instant.to_hms();
        second += u8::from(self.nanosecond >= NANOS_PER_SECOND);
        if (0..=9999).contains(&year) {
            write!(formatter, "{year:04}")?;
        } else {
            write!(formatter, "{year:+05}")?;
        }
        write!(
            formatter,
            "-{:02}-{day:02}T{hour:02}:{minute:02}:{second:02}",
            u8::from(month)
        )?;
        match self.nanosecond % NANOS_PER_SECOND {
            0 => {}
            nanos if nanos % 1_000_000 == 0 => write!(formatter, ".{:03}", nanos / 1_000_000)?,
            nanos if nanos % 1_000 == 0 => write!(formatter, ".{:06}", nanos / 1_000)?,
            nanos => write!(formatter, ".{nanos:09}")?,
        }
        formatter.write_str("Z")
    }
}

impl Serialize for AdvisoryTimestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for AdvisoryTimestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TimestampVisitor;

        impl de::Visitor<'_> for TimestampVisitor {
            type Value = AdvisoryTimestamp;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an advisory timestamp string")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                value.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_str(TimestampVisitor)
    }
}
