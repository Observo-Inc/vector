use std::{borrow::Cow, collections::BTreeMap, fmt::Debug, ops::Range};

use crate::encoding::format::common::get_serializer_schema_requirement;
use bytes::BytesMut;
use chrono::{DateTime, SecondsFormat, Utc};
use dyn_clone::DynClone;
use lookup::{OwnedTargetPath, PathPrefix};
use tokio_util::codec::Encoder;
use tracing::{error, warn};
use vector_common::get_hostname;
use vector_config_macros::configurable_component;
use vector_core::{config::{DataType, TimestampFormat}, event::{Event, LogEvent}, schema::{self, meaning::{self}}};
use vrl::{core::Value, value::KeyString};
use core::fmt::Write;

/// Timestamp resolution for RFC 5424 syslog messages.
#[configurable_component]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub enum TimeRes {
    /// Whole seconds.
    #[serde(alias = "sec", alias = "s")]
    Seconds,

    /// Milliseconds.
    #[serde(alias = "millis", alias = "ms")]
    #[default]
    Milliseconds,

    /// Microseconds.
    #[serde(alias = "micros", alias = "us")]
    Microseconds,
}

/// RFC 5424 syslog message format configuration.
#[configurable_component]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Rfc5424 {
    /// Timestamp resolution.
    #[serde(alias = "resolution", default)]
    res: TimeRes,

    /// Whether to include a 'Z' suffix for UTC timestamps.
    #[serde(alias = "use_z", default = "default_z")]
    z: bool,

    /// Whether to include a BOM (byte order mark) at the start of the message.
    #[serde(alias = "include_bom", alias = "with_bom", default = "default_bom")]
    bom: bool,
}

fn default_z() -> bool {
    true
}

fn default_bom() -> bool {
    false
}

impl Rfc5424 {
    /// Creates a new `Rfc5424` config.
    pub fn new(res: TimeRes, z: bool, bom: bool) -> Self {
        Rfc5424 { res, z, bom }
    }

    fn msg_prefix(&self) -> &'static str {
       if self.bom {
            "\u{FEFF}"
       } else {
            ""
       }
    }

    fn time_res(&self) -> SecondsFormat {
        match self.res {
            TimeRes::Seconds => SecondsFormat::Secs,
            TimeRes::Milliseconds => SecondsFormat::Millis,
            TimeRes::Microseconds => SecondsFormat::Micros,
        }
    }
}

impl Default for Rfc5424 {
    fn default() -> Self {
        Rfc5424::new(TimeRes::Milliseconds, true, false)
    }
}

/// The syslog message format.
#[configurable_component]
#[derive(Debug, Clone, Eq, PartialEq)]
#[serde(rename_all = "snake_case", tag = "rfc")]
pub enum Format {
    /// Syslog RFC 5424 compliant message format.
    #[serde(alias = "rfc5424", alias = "RFC_5424", alias = "5424")]
    Rfc5424(Rfc5424),

    /// Syslog RFC 3164 compliant message format.
    #[serde(alias = "rfc3164", alias = "RFC_3164", alias = "3164")]
    Rfc3164,
}

impl Default for Format {
    fn default() -> Self {
        Format::Rfc5424(Rfc5424::default())
    }
}

/// Config for truncating serialized messages.
#[configurable_component]
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct Truncation {
    /// Maximum length of the serialized message. If set, messages longer than this will be truncated.
    max_len: usize,

    /// String to append to truncated messages to indicate truncation.
    #[serde(alias = "elide", default)]
    elipsis: Option<String>,
}

impl Truncation {
    /// Creates a new `Truncation` config.
    pub const fn new(max_len: usize, elipsis: Option<String>) -> Self {
        Self { max_len, elipsis }
    }
}

/// Config used to build a `SyslogSerializer`.
#[configurable_component]
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct SyslogSerializerConfig {
    /// The syslog message format.
    #[serde(alias = "standard", alias = "std", default)]
    format: Format,

    /// Timestamp format (the rule for processing the timestamp attribute)
    #[serde(alias = "timestamp_format", alias = "ts_fmt", alias = "time_fmt", default)]
    ts_format: TimestampFormat,

    /// Configuration for truncating serialized messages. Can be useful in preventing fragmentation over UDP.
    #[serde(alias = "trunc", default)]
    truncate: Option<Truncation>,
}

impl SyslogSerializerConfig {
    /// Creates a new `SyslogSerializerConfig`.
    pub const fn new(format: Format, ts_format: TimestampFormat, truncate: Option<Truncation>) -> Self {
        Self { format, ts_format, truncate }
    }

    /// Build the `SyslogSerializer` from this configuration.
    pub fn build(&self) -> SyslogSerializer {
        self.build_inner(Box::new(NativeClock()))
    }

    /// Build the `SyslogSerializer` with clock
    pub(self) fn build_inner(&self, clock: Box<dyn Clock + Sync + Send + 'static>) -> SyslogSerializer {
        let this_host = get_hostname().expect("couldn't retrieve hostname");
        SyslogSerializer::new(self.clone(), this_host, clock)
    }

    /// The data type of events that are accepted by `SyslogSerializer`.
    pub fn input_type(&self) -> DataType {
        DataType::Log
    }

    /// The schema required by the serializer.
    pub fn schema_requirement(&self) -> schema::Requirement {
        get_serializer_schema_requirement()
    }
}

#[derive(Debug, Clone, Copy)]
enum Attr {
    Message,
    Host,
    Time,
    Priority,
    Facility,
    Severity,
    Service,
    MsgId,
    ProcId,
    SD,
}

impl Attr {
    fn path(&self) -> OwnedTargetPath {
        let vp = match self {
            Self::Message => meaning::MESSAGE,
            Self::Host => meaning::HOST,
            Self::Time => meaning::TIMESTAMP,
            Self::Priority => "priority",
            Self::Facility => "facility",
            Self::Severity => meaning::SEVERITY,
            Self::Service => meaning::SERVICE,
            Self::MsgId => "msgid",
            Self::ProcId => "procid",
            Self::SD => "sd",
        }.parse().unwrap();

        OwnedTargetPath{
            prefix: PathPrefix::Event,
            path: vp}
    }

    fn get<'a>(&self, log: &'a LogEvent) -> Option<&'a Value> {
        log.get(&self.path())
    }
}

/// Serializer that converts a log to syslog format.
#[derive(Debug, Clone)]
pub struct SyslogSerializer {
    cfg: SyslogSerializerConfig,
    dflt_host: String,
    clk: Box<dyn Clock + Sync + Send + 'static>,
    dflt_sd: BTreeMap<KeyString, Value>,
}
use Attr::*;

const DFLT_PRI: u8 = 13;

fn num_val(v: &Value, r: Range<u8>, dflt: u8) -> u8 {
    let v = match v {
        Value::Integer(v) => Ok(*v as u8),
        Value::Bytes(v) if v.len() <= 3 => String::from_utf8_lossy(&*v).parse::<u8>(),
        Value::Float(v) => Ok(**v as u8),
        _ => Ok(dflt),
    }.unwrap_or(dflt);
    if r.contains(&v) {
        v
    } else {
        dflt
    }
}

fn pri(l: &LogEvent) -> u8 {
    if let Some(pri) = Priority.get(l) {
        num_val(pri, 0u8..192u8, DFLT_PRI)
    } else if let (Some(facility), Some(sev)) = (Facility.get(l), Severity.get(l)) {
        num_val(facility, 0u8..24u8, 1u8) * 8 + num_val(sev, 0u8..8u8, 5)
    } else {
        DFLT_PRI
    }
}

fn tm(l: &LogEvent, fmt: &TimestampFormat, clk: &Box<dyn Clock + Sync + Send + 'static>) -> DateTime<Utc> {
    match Time.get(&l).map(|v| fmt.resolve(v)) {
        Some(Ok(ts)) => ts,
        Some(Err(e)) => {
            error!("Couldn't retrive event timestamp (defaulting to now), err: {}", e);
            clk.now()
        },
        None => {
            error!("Event has no timestamp field, defaulting to now");
            clk.now()
        },
    }
}

fn value<'a, T: ToOwned + ?Sized>(
    l: &'a LogEvent,
    a: Attr,
    dflt: &'a T,
    map: impl Fn(&Value) -> Option<Cow<'_, T>>,
) -> Cow<'a, T> {
    a.get(&l).and_then(map).unwrap_or_else(|| {
        error!("Event attribute {a:?} is either unset or has an unsupported type");
        Cow::Borrowed(dflt)
    })
}

fn str<'a>(l: &'a LogEvent, a: Attr, dflt: &'a str) -> Cow<'a, str> {
    value(l, a, dflt, |h| h.as_str())
}

fn host<'a>(l: &'a LogEvent, dflt: &'a str) -> Cow<'a, str> {
    str(l, Host, dflt)
}

pub(self) trait Clock : DynClone + Debug {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}
dyn_clone::clone_trait_object!(Clock);

#[derive(Debug, Clone)]
struct NativeClock();

impl Clock for NativeClock {}

fn valid_sd_id_char(c: char) -> bool {
    let is_ascii_printable = c >= '!' && c <= '~'; // ASCII 33-126
    let is_forbidden = c == '=' || c == ']' || c == '"' || c == ' '; // Explicitly forbidden
    is_ascii_printable && !is_forbidden
}

fn write_sd_id<'a>(input: Cow<'a, str>, buf: &mut BytesMut) -> Result<bool, std::fmt::Error> {
    let mut need_change = false;

    for c in input.chars() {
        if !valid_sd_id_char(c) {
            need_change = true;
            break;
        }
    }

    let result = if need_change {
       Cow::Owned(input.chars().filter(|c| valid_sd_id_char(*c)).collect())
    } else {
        input
    };

    // Handle truncation (Max 32 chars)
    let result = if result.len() > 32 {
        need_change = true;
        result[..32].into()
    } else {
        result
    };

    if result.is_empty() {
        warn!("Dropped syslog SD-ID: Input empty or invalid.");
        return Ok(false);
    }

    if need_change && result.len() > 0 {
        warn!( "Sanitized SD-ID: Input had invalid characters (or exceeded 32 chars). Using: '{}'", result);
    }

    write!(buf, "[{}", result).map(|_| true)
}

fn write_sd_value(k: &str, v: &Value, buf: &mut BytesMut) -> Result<(), std::fmt::Error> {
    let v = match v {
        Value::Bytes(s) => String::from_utf8_lossy(s.as_ref()).into_owned(),
        Value::Integer(i) => i.to_string(),
        Value::Float(n) => n.to_string(),
        Value::Boolean(b) => b.to_string(),
        _ => {
            warn!("Ignored (unsupported) syslog SD attribute value type for key '{}'", k);
            return Ok(());
        }
    };
    let v = v.replace('\\', r"\\").replace('"', r#"\""#).replace(']', r"\]");
    write!(buf, r#" {}="{}""#, k, v)
}

impl SyslogSerializer {
    fn new(cfg: SyslogSerializerConfig, dflt_host: String, clk: Box<dyn Clock + Sync + Send + 'static>) -> SyslogSerializer {
        SyslogSerializer{ cfg, dflt_host, clk, dflt_sd: BTreeMap::new()}
    }

    fn write_sd(&self, l: &LogEvent, buf: &mut BytesMut) -> Result<(), std::fmt::Error> {
        let sd = value(&l, SD, &self.dflt_sd, |sd| match sd {
            Value::Object(m) => Some(Cow::Borrowed(m)),
            _ => None,
        });

        if sd.is_empty() {
            write!(buf, "- ")?;
        } else {
            for (k, v) in sd.iter() {
                if write_sd_id(k.as_str().into(), buf)? {
                    match v {
                        Value::Object(m) => {
                            for (ak, av) in m {
                                write_sd_value(ak, av, buf)?;
                            }
                        },
                        _ => {
                            write_sd_value("value", v, buf)?;
                        }
                    }
                    write!(buf, "]")?;
                }
            }
            write!(buf, " ")?;
        }

        Ok(())
    }

    fn truncate_maybe(&self, buf: &mut BytesMut) {
        if let Some(trunc) = &self.cfg.truncate {
            if buf.len() > trunc.max_len {
                let elip = trunc.elipsis.as_deref().unwrap_or("");
                let elip_len = elip.len();
                if elip_len >= trunc.max_len {
                    error!("Truncating syslog message but elipsis length ({}) >= max_len ({}). Dropping elipsis.", elip_len, trunc.max_len);
                    buf.truncate(trunc.max_len);
                } else {
                    error!("Truncating syslog message from length {} to max_len {}.", buf.len(), trunc.max_len);
                    buf.truncate(trunc.max_len - elip_len);
                    buf.extend_from_slice(elip.as_bytes());
                }
            }
        }
    }

    fn encode_5424(&self, l: LogEvent, buf: &mut BytesMut, cfg: &Rfc5424) -> Result<(), std::fmt::Error> {
        let pri = pri(&l);
        let ts = tm(&l, &self.cfg.ts_format, &self.clk).to_rfc3339_opts(cfg.time_res(), cfg.z);
        let host = host(&l, self.dflt_host.as_str());
        let app = str(&l, Service, "-");
        let msg = str(&l, Message, "-");
        let msg_id = str(&l, MsgId, "-");
        let proc_id = value(&l, ProcId, "-", |v| match v {
            Value::Bytes(s) => Some(String::from_utf8_lossy(s.as_ref())),
            Value::Integer(i) => Some(Cow::Owned(i.to_string())),
            Value::Float(n) => Some(Cow::Owned(n.to_string())),
            _ => None,
        });
        let msg_prefix = cfg.msg_prefix();

        write!(buf, "<{pri}>1 {ts} {host} {app} {proc_id} {msg_id} ")?;
        self.write_sd(&l, buf)?;
        write!(buf, "{msg_prefix}{msg}")
    }

    fn encode_3164(&self, l: LogEvent, buf: &mut BytesMut) -> Result<(), std::fmt::Error> {
        let pri = pri(&l);
        let ts = tm(&l, &self.cfg.ts_format, &self.clk).format("%b %e %H:%M:%S");
        let host = host(&l, self.dflt_host.as_str());
        let msg = Message.get(&l).and_then(|v| v.as_str()).unwrap_or("-".into());
        write!(buf, "<{pri}>{ts} {host} {msg}")
    }
}

impl Encoder<Event> for SyslogSerializer {
    type Error = vector_common::Error;

    fn encode(&mut self, event: Event, buf: &mut BytesMut) -> Result<(), Self::Error> {
        if let Event::Log(event) = event {
            match &self.cfg.format {
                Format::Rfc5424(cfg) => self.encode_5424(event, buf, cfg),
                Format::Rfc3164 => self.encode_3164(event, buf),
            }.map_err(Box::new)?;

            self.truncate_maybe(buf);
            Ok(())
        } else {
            Ok(())
        }
    }

}

#[cfg(test)]
mod tests {
    use bytes::{Bytes, BytesMut};
    use chrono::DateTime;
    use rstest::rstest;
    use tracing_test::traced_test;
    use vector_core::{config::TimePrecision, event::LogEvent};
    use tracing::trace;

    use super::*;

    fn tm(s: &str) -> Value {
        let ts: DateTime<Utc> = s.parse().unwrap();
        Value::from(ts)
    }

    fn s(s: &'static str) -> Value {
        Value::Bytes(s.into())
    }

    fn m<const N: usize>(d: [(&str, Value); N]) -> Value {
        Value::Object(d.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    fn a<const N: usize>(d: [Value; N]) -> Value {
        Value::Array(d.into_iter().map(|v| v).collect())
    }

    fn r(rexp: &str) -> Value {
        Value::from(regex::Regex::new(rexp).unwrap())
    }

    fn e<const N: usize>(d: [(&str, Value); N]) -> Event {
        Event::Log(m(d).into())
    }

    fn h() -> String {
        get_hostname().expect("couldn't retrieve hostname")
    }

    #[derive(Debug, Clone)]
    struct FrozenClock(DateTime<Utc>);

    impl Clock for FrozenClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    #[rstest]
    #[case::host_msg_time(
        "<20>Jan 21 01:35:20 test.com Process crashed",
        SyslogSerializerConfig{
            format: Format::Rfc3164,
            ts_format: TimestampFormat::Native,
            truncate: None,
        },
        e([
            ("priority", 20.into()),
            ("host", s("test.com")),
            ("message", s("Process crashed")),
            ("timestamp", tm("2015-01-20T17:35:20.123456789−08:00"))]),
    )]
    #[case::host_nomsg_time_nopri(
        "<13>Jan 21 01:35:20 test.com -",
        SyslogSerializerConfig{
            format: Format::Rfc3164,
            ts_format: TimestampFormat::Native,
            truncate: None,
        },
        e([
            ("host", s("test.com")),
            ("timestamp", tm("2015-01-20T17:35:20.123456789−08:00"))]),
    )]
    #[case::host_msg_notime(
        "<20>Dec 17 07:00:48 test.com Process restarted!",
        SyslogSerializerConfig{
            format: Format::Rfc3164,
            ts_format: TimestampFormat::Native,
            truncate: None,
        },
        e([
            ("priority", 20.into()),
            ("host", s("test.com")),
            ("message", s("Process restarted!"))]),
    )]
    #[case::nohost_msg_time(
        format!("<20>Jan 21 01:35:20 {} Process restarted!", h()),
        SyslogSerializerConfig{
            format: Format::Rfc3164,
            ts_format: TimestampFormat::Native,
            truncate: None,
        },
        e([
            ("priority", 20.into()),
            ("message", s("Process restarted!")),
            ("timestamp", tm("2015-01-20T17:35:20.123456789−08:00"))]),
    )]
    #[case::with_numeric_time_nopri(
        "<13>Dec 17 08:58:35 foo.com Process restarted!",
        SyslogSerializerConfig{
            format: Format::Rfc3164,
            ts_format: TimestampFormat::Numeric(TimePrecision::Seconds),
            truncate: None,
        },
        e([
            ("host", s("foo.com")),
            ("message", s("Process restarted!")),
            ("timestamp", 1765961915i64.into())]),
    )]
    #[case::with_facility_and_severity(
        "<53>Dec 17 08:58:35 foo.com Process restarted!",
        SyslogSerializerConfig{
            format: Format::Rfc3164,
            ts_format: TimestampFormat::Numeric(TimePrecision::Seconds),
            truncate: None,
        },
        e([
            ("host", s("foo.com")),
            ("facility", 6.into()),
            ("severity", 5.into()),
            ("message", s("Process restarted!")),
            ("timestamp", 1765961915i64.into())]),
    )]
    #[case::truncate_msg(
        "<53>Dec 17 08:58:35 foo.com Process rest...",
        toml::from_str(
            r#"
            [std]
            rfc = "3164"
            [ts_fmt.numeric.sec]
            [trunc]
            max_len = 43
            elipsis = "..."
            "#,
        ).expect("Couldn't parse serializer config"),
        e([
            ("host", s("foo.com")),
            ("facility", 6.into()),
            ("severity", 5.into()),
            ("message", s("Process restarted!")),
            ("timestamp", 1765961915i64.into())]),
    )]
    fn test_rfc3164(
        #[case] out: impl Into<String>,
        #[case] cfg: SyslogSerializerConfig,
        #[case] evt: Event,
    ) {
        assert_eq!(serialize(cfg, evt), Bytes::from(out.into()));
    }

    #[rstest]
    #[case::no_sd_with_bom(
        "<20>1 2015-01-21T01:35:20.123Z test.com log-relay 8192 startup - \u{FEFF}Process restarted",
        SyslogSerializerConfig{
            format: Format::Rfc5424(Rfc5424::new(TimeRes::Milliseconds, true, true)),
            ts_format: TimestampFormat::Native,
            truncate: None,
        },
        e([
            ("priority", 20.into()),
            ("host", s("test.com")),
            ("msgid", s("startup")),
            ("procid", 8192.into()),
            ("service", s("log-relay")),
            ("message", s("Process restarted")),
            ("timestamp", tm("2015-01-20T17:35:20.123456789−08:00"))]),
    )]
    #[case::no_sd_no_bom_ms(
        "<20>1 2015-01-21T01:35:20.123Z test.com log-relay 8192 startup - Process restarted",
        SyslogSerializerConfig{
            format: Format::Rfc5424(Rfc5424::new(TimeRes::Milliseconds, true, false)),
            ts_format: TimestampFormat::Native,
            truncate: None,
        },
        e([
            ("priority", 20.into()),
            ("host", s("test.com")),
            ("msgid", s("startup")),
            ("procid", 8192.into()),
            ("service", s("log-relay")),
            ("message", s("Process restarted")),
            ("timestamp", tm("2015-01-20T17:35:20.123456789−08:00"))]),
    )]
    #[case::no_sd_with_bom_us(
        "<35>1 2025-12-17T08:58:35.123456Z test.com log-svc 8192 start - \u{FEFF}Process failed",
        toml::from_str(
            r#"
            [std]
            rfc = "rfc5424"
            res = "micros"
            z = true
            bom = true
            [ts_fmt.numeric.us]
            "#,
        ).expect("Couldn't parse serializer config"),
        e([
            ("severity", 3.into()),
            ("facility", 4.into()),
            ("host", s("test.com")),
            ("msgid", s("start")),
            ("procid", 8192.into()),
            ("service", s("log-svc")),
            ("message", s("Process failed")),
            ("timestamp", 1765961915123456i64.into())]),
    )]
    #[case::with_sd_no_bom(
        r#"<35>1 2025-12-17T08:58:35.123Z test.com log-svc 8192 start [t@5 value="3.14"][t._-!@3 value="va\"lue1"][t@1 a="b" e="true" f="co\"m\\ple\]x str"][t@2 c="d"][t@4 value="42"][thisissuchalongkeythatthisputsme x="y"] Process failed"#,
        toml::from_str(
            r#"
            [std]
            rfc = "rfc5424"
            [ts_fmt.numeric.millis]
            "#,
        ).expect("Couldn't parse serializer config"),
        e([
            ("severity", 3.into()),
            ("facility", 4.into()),
            ("host", s("test.com")),
            ("msgid", s("start")),
            ("procid", 8192.into()),
            ("service", s("log-svc")),
            ("sd", m([
                     ("this is such a long key that this puts message to shame", m([("x", s("y"))])),
                     ("t@1", m([("a", s("b")), ("e", true.into()), ("f", s("co\"m\\ple]x str"))])),
                     ("t@2", m([("c", s("d"))])),
                     (" ]\"   ", true.into()),
                     ("   ", s("this will be dropped, so will the entry before, and after!")),
                     ("", false.into()),
                     ("t._-!@3", s("va\"lue1")),
                     ("t @]\" = 5", 3.14.into()),
                     ("t@4", 42.into())])),
            ("message", s("Process failed")),
            ("timestamp", 1765961915123i64.into())]),
    )]
    #[case::with_sd_and_bom(
        "<35>1 2015-01-21T01:35:20.123456Z test.com log-svc 8192 start [t@1 a=\"b\" e=\"true\"][t@4 value=\"42\"] \u{FEFF}Process failed",
        toml::from_str(
            r#"
            [std]
            rfc = "rfc5424"
            bom = true
            res = "micros"
            [ts_fmt.num.us]
            "#,
        ).expect("Couldn't parse serializer config"),
        e([
            ("severity", 3.into()),
            ("facility", 4.into()),
            ("host", s("test.com")),
            ("msgid", s("start")),
            ("procid", 8192.into()),
            ("service", s("log-svc")),
            ("sd", m([
                     ("t@1", m([("a", s("b")), ("e", true.into())])),
                     ("t@4", 42.into())])),
            ("message", s("Process failed")),
            ("timestamp", tm("2015-01-20T17:35:20.123456789−08:00"))]),
    )]
    #[case::truncate_msg(
        "<35>1 2015-01-21T01:35:20.123456Z test.com log-svc 8192 start [t@1 a=\"b\" e=\"true\"][t@4 value=\"42\"] \u{FEFF}Proces...",
        toml::from_str(
            r#"
            [std]
            rfc = "rfc5424"
            bom = true
            res = "micros"
            [ts_fmt.num.us]
            [trunc]
            max_len = 111
            elipsis = "..."
            "#,
        ).expect("Couldn't parse serializer config"),
        e([
            ("severity", 3.into()),
            ("facility", 4.into()),
            ("host", s("test.com")),
            ("msgid", s("start")),
            ("procid", 8192.into()),
            ("service", s("log-svc")),
            ("sd", m([
                     ("t@1", m([("a", s("b")), ("e", true.into())])),
                     ("t@4", 42.into())])),
            ("message", s("Process failed")),
            ("timestamp", tm("2015-01-20T17:35:20.123456789−08:00"))]),
    )]
    #[case::truncate_msg_without_elipsis(
        "<35>1 2015-01-21T01:35:20.123456Z test.com log-svc 8192 start [t@1 a=\"b\" e=\"true\"][t@4 value=\"42\"] \u{FEFF}Process f",
        toml::from_str(
            r#"
            [std]
            rfc = "rfc5424"
            bom = true
            res = "micros"
            [ts_fmt.num.us]
            [trunc]
            max_len = 111
            "#,
        ).expect("Couldn't parse serializer config"),
        e([
            ("severity", 3.into()),
            ("facility", 4.into()),
            ("host", s("test.com")),
            ("msgid", s("start")),
            ("procid", 8192.into()),
            ("service", s("log-svc")),
            ("sd", m([
                     ("t@1", m([("a", s("b")), ("e", true.into())])),
                     ("t@4", 42.into())])),
            ("message", s("Process failed")),
            ("timestamp", tm("2015-01-20T17:35:20.123456789−08:00"))]),
    )]
    #[case::truncate_aggressive(
        "<35>1 2015!",
        toml::from_str(
            r#"
            [std]
            rfc = "rfc5424"
            bom = true
            res = "micros"
            [ts_fmt.num.us]
            [trunc]
            max_len = 11
            elide = "!"
            "#,
        ).expect("Couldn't parse serializer config"),
        e([
            ("severity", 3.into()),
            ("facility", 4.into()),
            ("host", s("test.com")),
            ("msgid", s("start")),
            ("procid", 8192.into()),
            ("service", s("log-svc")),
            ("sd", m([
                     ("t@1", m([("a", s("b")), ("e", true.into())])),
                     ("t@4", 42.into())])),
            ("message", s("Process failed")),
            ("timestamp", tm("2015-01-20T17:35:20.123456789−08:00"))]),
    )]
    #[case::truncate_msg_without_elipsis_when_too_long(
        "<35>1 2015-",
        toml::from_str(
            r#"
            [std]
            rfc = "rfc5424"
            bom = true
            res = "micros"
            [ts_fmt.num.us]
            [trunc]
            max_len = 11
            elipsis = "....????...."
            "#,
        ).expect("Couldn't parse serializer config"),
        e([
            ("severity", 3.into()),
            ("facility", 4.into()),
            ("host", s("test.com")),
            ("msgid", s("start")),
            ("procid", 8192.into()),
            ("service", s("log-svc")),
            ("sd", m([
                     ("t@1", m([("a", s("b")), ("e", true.into())])),
                     ("t@4", 42.into())])),
            ("message", s("Process failed")),
            ("timestamp", tm("2015-01-20T17:35:20.123456789−08:00"))]),
    )]
    #[case::unsupported_types_in_values_for_sd_entries(
        "<35>1 2015-01-21T01:35:20.123456Z test.com log-svc 8192 start [t@1 a=\"b\"][t@4][t@5][t@6][t@7] \u{FEFF}Process failed",
        toml::from_str(
            r#"
            [std]
            rfc = "rfc5424"
            bom = true
            res = "micros"
            [ts_fmt.num.us]
            "#,
        ).expect("Couldn't parse serializer config"),
        e([
            ("severity", 3.into()),
            ("facility", 4.into()),
            ("host", s("test.com")),
            ("msgid", s("start")),
            ("procid", 8192.into()),
            ("service", s("log-svc")),
            ("sd", m([
                     ("t@1", m([("a", s("b")), ("e", m([("foo", s("bar"))]))])),
                     ("t@4", a([s("baz"), s("quux")])),
                     ("t@5", m([("dt_tm", tm("2015-01-20T17:35:20.123456789−08:00"))])),
                     ("t@6", Value::Null),
                     ("t@7", r(r#"\d+"#)),
            ])),
            ("message", s("Process failed")),
            ("timestamp", tm("2015-01-20T17:35:20.123456789−08:00"))]),
    )]
    #[case::unsupported_value_in_sd(
        "<35>1 2015-01-21T01:35:20.123456Z test.com log-svc 8192 start - \u{FEFF}Process failed",
        toml::from_str(
            r#"
            [std]
            rfc = "rfc5424"
            bom = true
            res = "micros"
            [ts_fmt.num.us]
            "#,
        ).expect("Couldn't parse serializer config"),
        e([
            ("severity", 3.into()),
            ("facility", 4.into()),
            ("host", s("test.com")),
            ("msgid", s("start")),
            ("procid", 8192.into()),
            ("service", s("log-svc")),
            ("sd", r("a+")),
            ("message", s("Process failed")),
            ("timestamp", tm("2015-01-20T17:35:20.123456789−08:00"))]),
    )]
    #[traced_test]
    fn test_rfc5424(
        #[case] out: impl Into<String>,
        #[case] cfg: SyslogSerializerConfig,
        #[case] evt: Event,
    ) {
        trace!("Running test...");
        assert_eq!(serialize(cfg, evt), Bytes::from(out.into()));
    }

    #[test]
    fn config_defaults() {
        let cfg: SyslogSerializerConfig = toml::from_str("").expect("couldn't deserialize config");
        assert_eq!(
            cfg,
            SyslogSerializerConfig::new(
                Format::Rfc5424(Rfc5424::new(TimeRes::Milliseconds, true, false)),
                TimestampFormat::Native,
                None));
    }

    fn log_evt<K, V>(es: Vec<(K, V)>) -> LogEvent
    where K: AsRef<str>, V: Into<Value> {
        es.into_iter().collect()
    }

    #[test]
    fn priority_computation() {
        assert_eq!(pri(&LogEvent::from_str_legacy("foo")), 13);
        assert_eq!(
            pri(&log_evt(vec![("priority", 42)])),
            42);
        assert_eq!(
            pri(&log_evt(vec![("priority", 42.1)])),
            42);
        assert_eq!(
            pri(&log_evt(vec![("priority", "42")])),
            42);
        assert_eq!(
            pri(&log_evt(vec![("priority", "foo")])),
            DFLT_PRI);
        assert_eq!(
            pri(&log_evt(vec![("facility", 3)])),
            DFLT_PRI);
        assert_eq!(
            pri(&log_evt(vec![("severity", 4)])),
            DFLT_PRI);
        assert_eq!(
            pri(&log_evt(vec![("facility", 3), ("severity", 4)])),
            3 * 8 + 4);
        assert_eq!(
            pri(&log_evt(vec![("facility", "3"), ("severity", "4")])),
            3 * 8 + 4);
        assert_eq!(
            pri(&log_evt(vec![("facility", "three"), ("severity", "4")])),
            1 * 8 + 4);
        assert_eq!(
            pri(&log_evt(vec![("facility", "3"), ("severity", "four")])),
            3 * 8 + 5);
    }

    fn serialize(config: SyslogSerializerConfig, input: Event) -> Bytes {
        let mut buffer = BytesMut::new();
        let clock = Box::new(FrozenClock("2025-12-17T12:30:48.123456789+05:30".parse().unwrap()));
        config.build_inner(clock).encode(input, &mut buffer).unwrap();
        buffer.freeze()
    }
}
