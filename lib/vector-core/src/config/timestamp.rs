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
    #[serde(alias = "ns", alias = "nanos")]
    Nanoseconds,

    /// Microseconds precision (1/1,000,000 second)
    #[serde(alias = "us", alias = "micros")]
    Microseconds,

    /// Millisecond precision (1/1,000 second)
    #[serde(alias = "ms", alias = "millis")]
    Milliseconds,

    /// Second precision
    #[serde(alias = "s", alias = "sec")]
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
}
