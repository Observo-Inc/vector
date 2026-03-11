use std::{error::Error, fmt::Display, str::Utf8Error};

use chrono::{DateTime, Utc, NaiveDateTime, TimeZone};
use vector_config::configurable_component;
use vrl::core::Value;

#[configurable_component]
#[derive(Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// Precision levels for numeric timestamps
pub enum TimePrecision {
    /// Nanosecond precision (1/1,000,000,000 second)
    #[serde(alias = "ns", alias = "nanos", alias = "nanoseconds")]
    Nanoseconds,

    /// Microseconds precision (1/1,000,000 second)
    #[serde(alias = "us", alias = "micros", alias = "microseconds")]
    Microseconds,

    /// Millisecond precision (1/1,000 second)
    #[serde(alias = "ms", alias = "millis", alias = "milliseconds")]
    Milliseconds,

    /// Second precision
    #[serde(alias = "s", alias = "sec", alias = "seconds")]
    Seconds,
}

#[configurable_component]
#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
/// The format of the timestamp.
pub enum TimestampFormat {
    /// Use the default vector time format.
    #[serde(alias = "default", alias = "native")]
    #[default]
    Native,

    /// Numeric timestamp with configurable precision
    #[serde(alias = "numeric", alias = "num", alias = "numeric")]
    Numeric(TimePrecision),

    /// `Fmtstr`-style format string to format or parse timestamps.
    #[serde(alias = "string", alias = "str", alias = "fmtstr", alias = "fmt_str")]
    Fmtstr(String),
}

#[derive(Debug)]
pub enum TimestampResolutionError<'a> {
    InvalidUtf8(Utf8Error),
    InvalidTimestampString(&'a str, chrono::ParseError),
    NoTimestamp,
}

impl Display for TimestampResolutionError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimestampResolutionError::InvalidUtf8(e) => write!(f, "Invalid UTF-8 sequence: {}", e),
            TimestampResolutionError::InvalidTimestampString(s, e) => write!(f, "Invalid timestamp string: {} (err: {})", s, e),
            TimestampResolutionError::NoTimestamp => write!(f, "No timestamp value (or incompatible type) found"),
        }
    }
}

impl Error for TimestampResolutionError<'_> {}

impl TimestampFormat {
    fn numeric_time(i: i64, p: &TimePrecision) -> (i64, u32) {
        let (s, sub_s) = match p {
            TimePrecision::Seconds => {
                (i as f64, 0)
            }
            TimePrecision::Milliseconds => {
                ((i as f64) / 1000f64, (i as u64 % 1000) * 1_000_000)
            }
            TimePrecision::Microseconds => {
                ((i as f64) / 1000_000f64, ((i as u64  % 1_000_000) * 1000))
            }
            TimePrecision::Nanoseconds => {
                ((i as f64) / 1_000_000_000f64, (i as u64 % 1_000_000_000))
            }
        };
        (s as i64, sub_s as u32)
    }

    pub fn resolve<'a>(&self, v: &'a Value) -> Result<DateTime<Utc>, TimestampResolutionError<'a>>  {
        match (v, self) {
            (Value::Timestamp(ts), _) => {
                Ok(ts.clone())
            }
            (Value::Integer(i), Self::Numeric(precision)) => {
                let (sec, sub_sec) = Self::numeric_time(*i, precision);
                // TODO(OBE-7927): handle -ve seconds
                Ok(DateTime::from_timestamp(sec as i64, sub_sec as u32).expect("Invalid second / sub-sec-nanos"))
            }
            (Value::Float(i), Self::Numeric(precision)) => {
                let (sec, sub_sec) = Self::numeric_time(i.into_inner() as i64, precision);
                // TODO(OBE-7927): handle -ve seconds
                Ok(DateTime::from_timestamp(sec as i64, sub_sec as u32).expect("Invalid second / sub-sec-nanos"))
            }
            (Value::Bytes(b), TimestampFormat::Fmtstr(fmt)) => {
                let str = std::str::from_utf8(&b).map_err(TimestampResolutionError::InvalidUtf8)?;
                parse_with_format(str, &fmt).map_err(|e| TimestampResolutionError::InvalidTimestampString(str, e))
            }
            _ => Err(TimestampResolutionError::NoTimestamp),
        }
    }
}

fn parse_with_format(s: &str, fmt: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    // RFC3339 (recommended for inputs like "2024-06-15T12:34:56.789Z")
    if fmt.is_empty() || fmt.eq_ignore_ascii_case("rfc3339") {
        let dt = DateTime::parse_from_rfc3339(s)?;
        return Ok(dt.with_timezone(&Utc));
    }

    if is_iso8601_with_fractional_seconds_and_z(fmt){
        // Try RFC3339 parsing which handles variable-length fractional seconds
        if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
            return Ok(dt.with_timezone(&Utc));
        }
    }

    // If the user format contains a literal 'Z' (UTC) strip it and parse NaiveDateTime
    if fmt.contains('Z') {
        let s_trim = s.strip_suffix('Z').unwrap_or(s);
        let fmt_trim = fmt.trim_end_matches('Z');
        let naive = NaiveDateTime::parse_from_str(s_trim, fmt_trim)?;
        return Ok(Utc.from_utc_datetime(&naive));
    }


    // Try parsing as NaiveDateTime first (no offset in input), then fall back to DateTime parse
    if let Ok(naive) = NaiveDateTime::parse_from_str(s, fmt) {
        return Ok(Utc.from_utc_datetime(&naive));
    }

    // Otherwise expect the format to include an offset specifier like %z or %:z
    let dt = DateTime::parse_from_str(s, fmt)?;
    Ok(dt.with_timezone(&Utc))
}

fn is_iso8601_with_fractional_seconds_and_z(fmt: &str) -> bool {
    fmt.contains("%Y-%m-%dT%H:%M:%S")
        && (fmt.contains("%f") || fmt.contains("%N"))
        && fmt.ends_with("Z")
}

#[cfg(test)]
mod tests {
    use futures::future::Either;
    use ordered_float::NotNan;

    use super::*;

    #[test]
    fn test_timestamp_configurations() {
        struct TestCase {
            name: &'static str,
            timestamp_value: Value,
            config: TimestampFormat,
            expected: Either<(i64, u32), &'static str>,
        }

        let test_cases = vec![
            TestCase {
                name: "date-time",
                timestamp_value: Value::Timestamp("2015-01-20T17:35:20.000000004−08:00".parse().unwrap()),
                config: TimestampFormat::Native,
                expected: Either::Left((1421804120, 4)),
            },
            TestCase {
                name: "seconds precision",
                timestamp_value: Value::Integer(1638366107),
                config: TimestampFormat::Numeric(TimePrecision::Seconds),
                expected: Either::Left((1638366107, 0)),
            },
            TestCase {
                name: "milliseconds precision",
                timestamp_value: Value::Integer(1638366107983),
                config: TimestampFormat::Numeric(TimePrecision::Milliseconds),
                expected: Either::Left((1638366107, 983 * 1000_000)),
            },
            TestCase {
                name: "microseconds precision",
                timestamp_value: Value::Integer(1638366107983874),
                config:  TimestampFormat::Numeric(TimePrecision::Microseconds),
                expected: Either::Left((1638366107, 983874 * 1000)),
            },
            TestCase {
                name: "nanoseconds precision",
                timestamp_value: Value::Integer(1638366107983874983),
                config: TimestampFormat::Numeric(TimePrecision::Nanoseconds),
                expected: Either::Left((1638366107, 983874983)),
            },
            TestCase {
                name: "milliseconds precision float",
                timestamp_value: Value::Float(NotNan::new(1638366107983.031).expect("invalid test input")),
                config: TimestampFormat::Numeric(TimePrecision::Milliseconds),
                // OBE-7927: unsure if this is a real usecase, if so we can improve this
                expected: Either::Left((1638366107, 983 * 1000_000)),
            },
            TestCase {
                name: "strptime format with timezone",
                timestamp_value: Value::Bytes("1995 Aug 6 12:09:14.274 +0000".into()),
                config: TimestampFormat::Fmtstr("%Y %b %d %H:%M:%S%.3f %z".to_string()), //strftime
                expected: Either::Left((807710954, 274 * 1000_000)),
            },
            TestCase {
                name: "strptime format without zone in format",
                timestamp_value: Value::Bytes("1995-08-06T12:34:56.7890".into()),
                config: TimestampFormat::Fmtstr("%Y-%m-%dT%H:%M:%S.%f".to_string()),
                expected: Either::Left((807712496, 7890)),
            },
            TestCase {
                name: "unparsable date",
                timestamp_value: Value::Bytes("abcdefgh".into()),
                config: TimestampFormat::Fmtstr("%Y-%m-%dT%H:%M:%S.%f".to_string()),
                expected: Either::Right("Invalid timestamp string"),
            },
            TestCase {
                name: "no data",
                timestamp_value: Value::Null,
                config: TimestampFormat::Native,
                expected: Either::Right("No timestamp value (or incompatible type) found"),
            },
            TestCase {
                name: "numeric timestamp with strptime format config",
                timestamp_value: Value::Integer(100200300400),
                config:  TimestampFormat::Fmtstr("%Y-%m-%dT%H:%M:%S.%f".to_string()),
                expected: Either::Right("No timestamp value (or incompatible type) found"),
            },
            TestCase {
                name: "invalid utf-8",
                timestamp_value: Value::Bytes(b"\xFF"[..].into()),
                config: TimestampFormat::Fmtstr("%Y-%m-%dT%H:%M:%S.%f".to_string()),
                expected: Either::Right("Invalid UTF-8 sequence"),
            },
            TestCase {
                name: "Native instead of bytes",
                timestamp_value: Value::Timestamp("2015-01-20T17:35:20.000000004−08:00".parse().unwrap()),
                config: TimestampFormat::Fmtstr("%Y-%m-%dT%H:%M:%S.%f".to_string()),
                expected: Either::Left((1421804120, 4)),
            }];

        for test_case in test_cases {
            match (test_case.config.resolve(&test_case.timestamp_value), test_case.expected) {
                (Ok(dt), Either::Left(e)) => {
                    assert_eq!(
                        (dt.timestamp(), dt.timestamp_subsec_nanos()),
                        e,
                        "Test case '{}' failed: unexpected (seconds, ns)", test_case.name);
                },
                (Err(a_err), Either::Right(e_err)) => {
                    let err_str = a_err.to_string();
                    assert!(
                        err_str.contains(e_err),
                        "Test case '{}' failed: expected error containing '{}', got '{}'",
                        test_case.name, e_err, err_str);
                },
                (Ok(_), Either::Right(e_err)) => {
                    panic!(
                        "Test case '{}' failed: expected error containing '{}', but got Ok",
                        test_case.name, e_err);
                },
                (Err(a_err), Either::Left(e)) => {
                    panic!(
                        "Test case '{}' failed: expected Ok({:?}), but got error '{}'",
                        test_case.name, e, a_err);
                }
            }
        }
    }

    #[test]
    fn test_parse_with_format() {
        struct TestCase {
            name: &'static str,
            input: &'static str,
            format: &'static str,
            expected: Result<DateTime<Utc>, chrono::ParseError>,
        }

        fn utc(s: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
            Ok(DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc))
        }

        fn err(fmt: &str, input: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
            // Deliberately trigger a chrono::ParseError using a bad format+input pair
            DateTime::parse_from_str(input, fmt).map(|dt| dt.with_timezone(&Utc))
        }

        let testcases = vec![
            // ── RFC 3339 fast path ────────────────────────────────────────────────
            TestCase {
                name: "rfc3339 - nanosecond precision with Z",
                input: "2026-01-29T21:52:10.647123456Z",
                format: "rfc3339",
                expected: utc("2026-01-29T21:52:10.647123456Z"),
            },
            TestCase {
                name: "rfc3339 - microsecond precision with Z",
                input: "2026-01-29T21:52:10.647123Z",
                format: "rfc3339",
                expected: utc("2026-01-29T21:52:10.647123Z"),
            },
            TestCase {
                name: "rfc3339 - millisecond precision with Z",
                input: "2026-01-29T21:52:10.647Z",
                format: "rfc3339",
                expected: utc("2026-01-29T21:52:10.647Z"),
            },
            TestCase {
                name: "rfc3339 - no fractional seconds with Z",
                input: "2026-01-29T21:52:10Z",
                format: "rfc3339",
                expected: utc("2026-01-29T21:52:10Z"),
            },
            TestCase {
                name: "rfc3339 - with positive offset",
                input: "2026-01-29T21:52:10+05:30",
                format: "rfc3339",
                expected: utc("2026-01-29T16:22:10Z"),
            },
            TestCase {
                name: "rfc3339 - with negative offset",
                input: "2026-01-29T21:52:10-07:00",
                format: "rfc3339",
                expected: utc("2026-01-30T04:52:10Z"),
            },
            TestCase {
                name: "rfc3339 - empty format string defaults to rfc3339",
                input: "2026-01-29T21:52:10.123456Z",
                format: "",
                expected: utc("2026-01-29T21:52:10.123456Z"),
            },

            // ── Literal Z suffix formats ──────────────────────────────────────────
            TestCase {
                name: "literal Z - nanosecond (9-digit) fractional seconds",
                input: "2026-01-29T21:52:10.647189854Z",
                format: "%Y-%m-%dT%H:%M:%S.%fZ",
                expected: utc("2026-01-29T21:52:10.647189854Z"),
            },
            TestCase {
                name: "literal Z - microsecond (6-digit) fractional seconds",
                input: "2026-01-29T21:52:10.647189Z",
                format: "%Y-%m-%dT%H:%M:%S.%fZ",
                expected: utc("2026-01-29T21:52:10.647189Z"),
            },
            TestCase {
                name: "literal Z - millisecond (3-digit) fractional seconds",
                input: "2026-01-29T21:52:10.647Z",
                format: "%Y-%m-%dT%H:%M:%S.%fZ",
                expected: utc("2026-01-29T21:52:10.647Z"),
            },
            TestCase {
                name: "literal Z - no fractional seconds",
                input: "2026-01-29T21:52:10Z",
                format: "%Y-%m-%dT%H:%M:%SZ",
                expected: utc("2026-01-29T21:52:10Z"),
            },
            TestCase {
                name: "literal Z - date and time with slash separators",
                input: "29/01/2026 21:52:10Z",
                format: "%d/%m/%Y %H:%M:%SZ",
                expected: utc("2026-01-29T21:52:10Z"),
            },

            // ── Naive (no offset) formats — assumed UTC ───────────────────────────
            TestCase {
                name: "naive - datetime no fractional seconds",
                input: "2026-01-29T21:52:10",
                format: "%Y-%m-%dT%H:%M:%S",
                expected: utc("2026-01-29T21:52:10Z"),
            },
            TestCase {
                name: "naive - datetime with microseconds",
                input: "2026-01-29T21:52:10.123456",
                format: "%Y-%m-%dT%H:%M:%S.%f",
                expected: utc("2026-01-29T21:52:10.000123456Z"),
            },
            TestCase {
                name: "naive - datetime with nanoseconds normalized to microseconds",
                input: "2026-01-29T21:52:10.123456789",
                format: "%Y-%m-%dT%H:%M:%S.%f",
                expected: utc("2026-01-29T21:52:10.123456789Z"),
            },
            TestCase {
                name: "naive - slash date format",
                input: "29/01/2026 21:52:10",
                format: "%d/%m/%Y %H:%M:%S",
                expected: utc("2026-01-29T21:52:10Z"),
            },
            TestCase {
                name: "naive - space separated date",
                input: "2026-01-29 21:52:10",
                format: "%Y-%m-%d %H:%M:%S",
                expected: utc("2026-01-29T21:52:10Z"),
            },
            TestCase {
                name: "naive - with %NZ",
                input: "2026-01-29T21:52:10.647123456Z",
                format: "%Y-%m-%dT%H:%M:%S.%NZ",
                expected: utc("2026-01-29T21:52:10.647123456Z"),
            },

            // ── Offset-aware formats ──────────────────────────────────────────────
            TestCase {
                name: "offset - compact %z positive",
                input: "2026-01-29T21:52:10+0530",
                format: "%Y-%m-%dT%H:%M:%S%z",
                expected: utc("2026-01-29T21:52:10Z"),
            },
            TestCase {
                name: "offset - colon %:z negative",
                input: "2026-01-29T21:52:10-07:00",
                format: "%Y-%m-%dT%H:%M:%S%:z",
                expected: utc("2026-01-29T21:52:10Z"),
            },
            TestCase {
                name: "offset - with microseconds and offset",
                input: "2026-01-29T21:52:10.123456+05:30",
                format: "%Y-%m-%dT%H:%M:%S.%f%:z",
                expected: utc("2026-01-29T21:52:10.000123456Z"),
            },
            TestCase {
                name: "offset - with nanoseconds normalized and offset",
                input: "2026-01-29T21:52:10.123456789+05:30",
                format: "%Y-%m-%dT%H:%M:%S.%f%:z",
                expected: utc("2026-01-29T21:52:10.123456789Z"),
            },

            // ── Edge cases ────────────────────────────────────────────────────────
            TestCase {
                name: "edge - midnight UTC",
                input: "2026-01-29T00:00:00Z",
                format: "rfc3339",
                expected: utc("2026-01-29T00:00:00Z"),
            },
            TestCase {
                name: "edge - end of day UTC",
                input: "2026-01-29T23:59:59.999999Z",
                format: "rfc3339",
                expected: utc("2026-01-29T23:59:59.999999Z"),
            },
            TestCase {
                name: "edge - leap day",
                input: "2024-02-29T12:00:00Z",
                format: "rfc3339",
                expected: utc("2024-02-29T12:00:00Z"),
            },
            TestCase {
                name: "edge - nanoseconds",
                input: "2026-01-29T21:52:10.000000999Z",
                format: "%Y-%m-%dT%H:%M:%S.%fZ",
                expected: utc("2026-01-29T21:52:10.000000999Z"),
            },
            TestCase {
                name: "edge - %f%Z",
                input: "2026-01-29T21:52:10.6471234Z",
                format: "%Y-%m-%dT%H:%M:%S.%f%Z",
                expected: utc("2026-01-29T21:52:10.6471234Z"),
            },
            TestCase {
                name: "edge - 5 precision",
                input: "2026-01-29T21:52:10.00999Z",
                format: "%Y-%m-%dT%H:%M:%S.%fZ",
                expected: utc("2026-01-29T21:52:10.009990Z"),
            },
            TestCase {
                name: "edge - 4 precision",
                input: "2026-01-29T21:52:10.0999Z",
                format: "%Y-%m-%dT%H:%M:%S.%fZ",
                expected: utc("2026-01-29T21:52:10.099900Z"),
            },

            // ── Error cases ───────────────────────────────────────────────────────
            TestCase {
                name: "error - completely invalid input",
                input: "not-a-timestamp",
                format: "rfc3339",
                expected: err("%Y-%m-%dT%H:%M:%S%.fZ", "not-a-timestamp"),
            },
            TestCase {
                name: "error - mismatched format and input",
                input: "2026-01-29T21:52:10Z",
                format: "%d/%m/%Y %H:%M:%S",
                expected: err("%d/%m/%Y %H:%M:%S", "2026-01-29T21:52:10Z"),
            },
            TestCase {
                name: "error - invalid month",
                input: "2026-13-29T21:52:10Z",
                format: "rfc3339",
                expected: err("%Y-%m-%dT%H:%M:%S%.fZ", "2026-13-29T21:52:10Z"),
            },
            TestCase {
                name: "error - invalid day",
                input: "2026-01-32T21:52:10Z",
                format: "rfc3339",
                expected: err("%Y-%m-%dT%H:%M:%S%.fZ", "2026-01-32T21:52:10Z"),
            },
        ];

        for test_case in testcases {
            match (parse_with_format(test_case.input, test_case.format), test_case.expected) {
                (Ok(actual_dt), Ok(expected_dt)) => {
                    assert_eq!(actual_dt, expected_dt, "Test case '{}' failed", test_case.name);
                },
                (Err(actual_err), Err(expected_err)) => {
                    assert_eq!(actual_err.to_string(), expected_err.to_string(), "Test case '{}' failed", test_case.name);
                },
                (Ok(actual_dt), Err(expected_err)) => {
                    panic!("Test case '{}' failed: expected error '{}', but got Ok({:?})", test_case.name, expected_err, actual_dt);
                },
                (Err(actual_err), Ok(expected_dt)) => {
                    panic!("Test case '{}' failed: expected Ok({:?}), but got error '{}'", test_case.name, expected_dt, actual_err);
                }
            }
        }
    }
}
