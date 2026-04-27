use bytes::Bytes;
use chrono::Utc;
use csv_core::ReadFieldResult;
use derivative::Derivative;
use smallvec::{smallvec, SmallVec};
use std::sync::{Arc, Mutex};
use vector_config::configurable_component;
use vector_core::{
    config::{log_schema, DataType, LogNamespace},
    event::Event,
    schema,
};
use vrl::value::Kind;

use super::Deserializer;

/// Config used to build a `CsvDeserializer`.
#[configurable_component]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CsvDeserializerConfig {
    /// CSV-specific decoding options.
    #[serde(default, skip_serializing_if = "vector_core::serde::is_default")]
    pub csv: CsvDeserializerOptions,
}

/// CSV-specific decoding options.
#[configurable_component]
#[derive(Debug, Clone, PartialEq, Eq, Derivative)]
#[derivative(Default)]
pub struct CsvDeserializerOptions {
    /// Column names for the CSV data.
    ///
    /// If specified, these are used as field keys in the emitted events.
    /// If not specified, behavior depends on `has_header`:
    /// - `has_header: true` (default): the first row is consumed as headers.
    /// - `has_header: false`: fields are returned as an array in `message`.
    #[serde(default)]
    pub headers: Option<Vec<String>>,

    /// The field delimiter character. Defaults to `,`.
    #[serde(default)]
    pub delimiter: Option<char>,

    /// Whether the first row is a header row. Defaults to `true` when
    /// `headers` is not set, `false` when `headers` is set.
    #[serde(default)]
    pub has_header: Option<bool>,
}

impl CsvDeserializerConfig {
    /// Build the `CsvDeserializer` from this configuration.
    pub fn build(&self) -> CsvDeserializer {
        CsvDeserializer::from(self)
    }

    /// Return the type of event built by this deserializer.
    pub fn output_type(&self) -> DataType {
        DataType::Log
    }

    /// The schema produced by the deserializer.
    pub fn schema_definition(&self, log_namespace: LogNamespace) -> schema::Definition {
        match log_namespace {
            LogNamespace::Legacy => {
                let mut definition =
                    schema::Definition::empty_legacy_namespace().unknown_fields(Kind::bytes());

                if let Some(timestamp_key) = log_schema().timestamp_key() {
                    definition = definition.try_with_field(
                        timestamp_key,
                        Kind::bytes().or_timestamp(),
                        Some("timestamp"),
                    );
                }
                definition
            }
            LogNamespace::Vector => {
                schema::Definition::new_with_default_metadata(Kind::bytes(), [log_namespace])
            }
        }
    }
}

/// Streaming state maintained across `parse()` calls.
struct StreamingCsvState {
    reader: csv_core::Reader,
    /// Partial field data accumulated when input is exhausted mid-field.
    field_buf: Vec<u8>,
    /// Fields completed so far in the current (possibly partial) record.
    pending_fields: Vec<String>,
    /// Headers extracted from the first record, or configured by the user.
    headers: Option<Vec<String>>,
    /// Whether the first record should be treated as a header row.
    has_header: bool,
    /// Whether the first record has been consumed (as header or data).
    first_record_done: bool,
}

impl StreamingCsvState {
    /// Drain `field_buf` into a completed field string and push to `pending_fields`.
    fn finish_field(&mut self, extra: &[u8]) {
        self.field_buf.extend_from_slice(extra);
        let val = String::from_utf8_lossy(&self.field_buf).into_owned();
        self.field_buf.clear();
        self.pending_fields.push(val);
    }
}

/// Deserializer that builds `Event`s from a byte frame containing CSV data.
///
/// Uses `csv-core` (BurntSushi's zero-alloc DFA state machine) which:
/// - Never panics, never returns errors — always finds *a* parse
/// - Properly handles quoted fields containing newlines, commas, escaped quotes
/// - Supports streaming: maintains parser state across `parse()` calls via
///   `Arc<Mutex<StreamingCsvState>>`, so partial data works correctly
#[derive(Clone)]
pub struct CsvDeserializer {
    state: Arc<Mutex<StreamingCsvState>>,
}

impl std::fmt::Debug for CsvDeserializer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CsvDeserializer").finish()
    }
}

impl Default for CsvDeserializer {
    fn default() -> Self {
        CsvDeserializerConfig::default().build()
    }
}

impl From<&CsvDeserializerConfig> for CsvDeserializer {
    fn from(config: &CsvDeserializerConfig) -> Self {
        let delimiter = config.csv.delimiter.map(|c| c as u8).unwrap_or(b',');
        let has_header = config
            .csv
            .has_header
            .unwrap_or(config.csv.headers.is_none());

        Self {
            state: Arc::new(Mutex::new(StreamingCsvState {
                reader: csv_core::ReaderBuilder::new().delimiter(delimiter).build(),
                field_buf: Vec::with_capacity(256),
                pending_fields: Vec::with_capacity(16),
                headers: config.csv.headers.clone(),
                has_header,
                first_record_done: config.csv.headers.is_some(),
            })),
        }
    }
}

impl CsvDeserializer {
    /// Feed bytes into csv-core, accumulating partial state across calls.
    /// Returns events for any complete records found in this chunk.
    fn process_bytes(
        state: &mut StreamingCsvState,
        input: &[u8],
        log_namespace: LogNamespace,
        timestamp: chrono::DateTime<Utc>,
    ) -> SmallVec<[Event; 1]> {
        let mut events = SmallVec::new();
        let mut output = vec![0u8; input.len().max(256)];
        let mut pos = 0;

        loop {
            // Don't pass empty input to csv-core — it interprets &[] as EOF.
            if pos >= input.len() {
                break;
            }

            let (result, nin, nout) = state.reader.read_field(&input[pos..], &mut output);
            pos += nin;

            match result {
                ReadFieldResult::InputEmpty => {
                    state.field_buf.extend_from_slice(&output[..nout]);
                    break;
                }
                ReadFieldResult::Field { record_end } => {
                    if state.field_buf.is_empty() {
                        state.pending_fields.push(
                            String::from_utf8_lossy(&output[..nout]).into_owned(),
                        );
                    } else {
                        state.finish_field(&output[..nout]);
                    }
                    if record_end {
                        Self::emit_record(state, log_namespace, timestamp, &mut events);
                    }
                }
                ReadFieldResult::OutputFull => {
                    state.field_buf.extend_from_slice(&output[..nout]);
                }
                ReadFieldResult::End => {
                    if nout > 0 || !state.field_buf.is_empty() {
                        state.finish_field(&output[..nout]);
                    }
                    if !state.pending_fields.is_empty() {
                        Self::emit_record(state, log_namespace, timestamp, &mut events);
                    }
                    break;
                }
            }
        }

        events
    }

    /// Signal EOF to csv-core and flush any remaining partial record.
    /// Handles records not terminated by `\n` (e.g., last line of file).
    fn flush_eof(
        state: &mut StreamingCsvState,
        log_namespace: LogNamespace,
        timestamp: chrono::DateTime<Utc>,
    ) -> SmallVec<[Event; 1]> {
        let mut events = SmallVec::new();
        let mut output = [0u8; 1];

        loop {
            let (result, _, nout) = state.reader.read_field(&[], &mut output);
            if nout > 0 {
                state.field_buf.extend_from_slice(&output[..nout]);
            }
            match result {
                ReadFieldResult::Field { record_end } => {
                    state.finish_field(&[]);
                    if record_end {
                        Self::emit_record(state, log_namespace, timestamp, &mut events);
                    }
                }
                ReadFieldResult::End => {
                    if !state.field_buf.is_empty() {
                        state.finish_field(&[]);
                    }
                    if !state.pending_fields.is_empty() {
                        Self::emit_record(state, log_namespace, timestamp, &mut events);
                    }
                    break;
                }
                _ => {}
            }
        }
        // Reset DFA for next parse() call; headers/config state preserved.
        state.reader.reset();
        events
    }

    /// Complete a record: capture as headers or emit as event.
    fn emit_record(
        state: &mut StreamingCsvState,
        log_namespace: LogNamespace,
        timestamp: chrono::DateTime<Utc>,
        events: &mut SmallVec<[Event; 1]>,
    ) {
        if !state.first_record_done && state.has_header {
            state.headers = Some(state.pending_fields.drain(..).collect());
            state.first_record_done = true;
            return;
        }
        state.first_record_done = true;

        let log = if let Some(ref hdrs) = state.headers {
            let mut obj = vrl::value::ObjectMap::new();
            for (i, field) in state.pending_fields.iter().enumerate() {
                let key = if i < hdrs.len() {
                    hdrs[i].clone()
                } else {
                    format!("column_{}", i)
                };
                obj.insert(key.into(), vrl::value::Value::from(field.clone()));
            }
            vrl::value::Value::Object(obj)
        } else {
            let arr: Vec<vrl::value::Value> = state
                .pending_fields
                .iter()
                .map(|f| vrl::value::Value::from(f.clone()))
                .collect();
            let mut obj = vrl::value::ObjectMap::new();
            obj.insert("message".into(), vrl::value::Value::Array(arr));
            vrl::value::Value::Object(obj)
        };
        state.pending_fields.clear();

        let mut event = Event::from(vector_core::event::LogEvent::from(log));
        if log_namespace == LogNamespace::Legacy {
            if let Some(timestamp_key) = log_schema().timestamp_key_target_path() {
                let log = event.as_mut_log();
                if !log.contains(timestamp_key) {
                    log.insert(timestamp_key, timestamp);
                }
            }
        }
        events.push(event);
    }
}

impl Deserializer for CsvDeserializer {
    fn parse(
        &self,
        bytes: Bytes,
        log_namespace: LogNamespace,
    ) -> vector_common::Result<SmallVec<[Event; 1]>> {
        if bytes.is_empty() {
            return Ok(smallvec![]);
        }

        let timestamp = Utc::now();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());

        let mut events = Self::process_bytes(&mut state, &bytes, log_namespace, timestamp);
        events.extend(Self::flush_eof(&mut state, log_namespace, timestamp));

        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vector_core::config::log_schema;
    use vrl::core::Value;

    #[test]
    fn deserialize_csv_simple() {
        let input = Bytes::from("host,message,severity\nserver01,hello,info\nserver02,world,warning");
        let config = CsvDeserializerConfig::default();

        for namespace in [LogNamespace::Legacy, LogNamespace::Vector] {
            let deserializer = config.build();
            let events = deserializer.parse(input.clone(), namespace).unwrap();
            assert_eq!(events.len(), 2);

            let event1 = events[0].as_log();
            assert_eq!(event1.get("host").unwrap(), &Value::from("server01"));
            assert_eq!(event1.get("message").unwrap(), &Value::from("hello"));
            assert_eq!(event1.get("severity").unwrap(), &Value::from("info"));

            let event2 = events[1].as_log();
            assert_eq!(event2.get("host").unwrap(), &Value::from("server02"));
            assert_eq!(event2.get("message").unwrap(), &Value::from("world"));
            assert_eq!(event2.get("severity").unwrap(), &Value::from("warning"));
        }
    }

    #[test]
    fn deserialize_csv_multiline_quoted_fields() {
        let input = Bytes::from(
            "host,message,severity\nserver01,\"this is a\nmulti-line\nmessage\",warning\nserver02,simple,info",
        );
        let deserializer = CsvDeserializerConfig::default().build();

        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();
        assert_eq!(events.len(), 2);

        let event1 = events[0].as_log();
        assert_eq!(event1.get("host").unwrap(), &Value::from("server01"));
        assert_eq!(
            event1.get("message").unwrap(),
            &Value::from("this is a\nmulti-line\nmessage")
        );
        assert_eq!(event1.get("severity").unwrap(), &Value::from("warning"));
    }

    #[test]
    fn deserialize_csv_heavily_multiline() {
        let input = Bytes::from(
            r#"host,message,details
server01,"line 1
line 2
line 3","error details:
  code: 500
  reason: internal"
server02,"ok","all good""#,
        );
        let deserializer = CsvDeserializerConfig::default().build();

        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();
        assert_eq!(events.len(), 2);

        let event1 = events[0].as_log();
        assert_eq!(event1.get("host").unwrap(), &Value::from("server01"));
        assert_eq!(
            event1.get("message").unwrap(),
            &Value::from("line 1\nline 2\nline 3")
        );
        assert_eq!(
            event1.get("details").unwrap(),
            &Value::from("error details:\n  code: 500\n  reason: internal")
        );
    }

    #[test]
    fn deserialize_csv_quoted_commas() {
        let input = Bytes::from("name,location\n\"Doe, John\",\"New York, NY\"\nJane,Boston");
        let deserializer = CsvDeserializerConfig::default().build();

        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();
        assert_eq!(events.len(), 2);

        let event1 = events[0].as_log();
        assert_eq!(event1.get("name").unwrap(), &Value::from("Doe, John"));
        assert_eq!(event1.get("location").unwrap(), &Value::from("New York, NY"));
    }

    #[test]
    fn deserialize_csv_with_configured_headers() {
        let input = Bytes::from("server01,hello,info\nserver02,world,warning");
        let config = CsvDeserializerConfig {
            csv: CsvDeserializerOptions {
                headers: Some(vec![
                    "host".to_string(),
                    "message".to_string(),
                    "severity".to_string(),
                ]),
                ..Default::default()
            },
        };
        let deserializer = config.build();

        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();
        assert_eq!(events.len(), 2);

        let event1 = events[0].as_log();
        assert_eq!(event1.get("host").unwrap(), &Value::from("server01"));
        assert_eq!(event1.get("message").unwrap(), &Value::from("hello"));
    }

    #[test]
    fn deserialize_csv_no_headers_returns_array() {
        let input = Bytes::from("server01,hello,info");
        let config = CsvDeserializerConfig {
            csv: CsvDeserializerOptions {
                has_header: Some(false),
                ..Default::default()
            },
        };
        let deserializer = config.build();

        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();
        assert_eq!(events.len(), 1);

        let event = events[0].as_log();
        assert_eq!(
            event.get("message").unwrap(),
            &Value::Array(vec![
                Value::from("server01"),
                Value::from("hello"),
                Value::from("info"),
            ])
        );
    }

    #[test]
    fn deserialize_csv_custom_delimiter() {
        let input = Bytes::from("host\tmessage\nserver01\thello");
        let config = CsvDeserializerConfig {
            csv: CsvDeserializerOptions {
                delimiter: Some('\t'),
                ..Default::default()
            },
        };
        let deserializer = config.build();

        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();
        assert_eq!(events.len(), 1);

        let event = events[0].as_log();
        assert_eq!(event.get("host").unwrap(), &Value::from("server01"));
        assert_eq!(event.get("message").unwrap(), &Value::from("hello"));
    }

    #[test]
    fn deserialize_csv_empty() {
        let deserializer = CsvDeserializerConfig::default().build();
        let events = deserializer
            .parse(Bytes::from(""), LogNamespace::Vector)
            .unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn deserialize_csv_legacy_adds_timestamp() {
        let input = Bytes::from("host\nserver01");
        let deserializer = CsvDeserializerConfig::default().build();

        let events = deserializer.parse(input, LogNamespace::Legacy).unwrap();
        assert_eq!(events.len(), 1);

        let event = events[0].as_log();
        assert!(event
            .get((
                lookup::PathPrefix::Event,
                log_schema().timestamp_key().unwrap()
            ))
            .is_some());
    }

    #[tokio::test]
    async fn bytes_framing_csv_decoder_multiline_fields() {
        use crate::actions::Decoder;
        use crate::decoding::{Deserializer as DeserializerEnum, Framer};
        use crate::BytesDecoder;
        use bytes::Bytes;
        use futures::{stream, StreamExt};
        use tokio_util::{codec::FramedRead, io::StreamReader};

        let csv_data =
            "host,message,severity\nserver01,\"multi\nline\nlog\",warning\nserver02,ok,info";

        let iter = stream::iter([csv_data].into_iter().map(Bytes::from));
        let stream = iter.map(Ok::<_, std::io::Error>);
        let reader = StreamReader::new(stream);

        let decoder = Decoder::new(
            Framer::Bytes(BytesDecoder::new()),
            DeserializerEnum::Csv(CsvDeserializerConfig::default().build()),
        );
        let mut stream = FramedRead::new(reader, decoder);

        let next = stream.next().await.unwrap();
        let events = next.unwrap().0;
        assert_eq!(events.len(), 2);

        let event1 = events[0].as_log();
        assert_eq!(event1.get("host").unwrap(), &Value::from("server01"));
        assert_eq!(
            event1.get("message").unwrap(),
            &Value::from("multi\nline\nlog")
        );

        assert!(stream.next().await.is_none());
    }

    // ── Streaming tests ─────────────────────────────────────────────────

    #[test]
    fn deserialize_csv_streaming_partial_record() {
        let config = CsvDeserializerConfig {
            csv: CsvDeserializerOptions {
                headers: Some(vec![
                    "host".to_string(),
                    "message".to_string(),
                    "severity".to_string(),
                ]),
                ..Default::default()
            },
        };
        let deserializer = config.build();
        let timestamp = Utc::now();

        {
            let mut state = deserializer.state.lock().unwrap();
            let events =
                CsvDeserializer::process_bytes(&mut state, b"server01,hel", LogNamespace::Vector, timestamp);
            assert!(events.is_empty());
            assert!(!state.field_buf.is_empty() || !state.pending_fields.is_empty());
        }

        {
            let mut state = deserializer.state.lock().unwrap();
            let events =
                CsvDeserializer::process_bytes(&mut state, b"lo,info\n", LogNamespace::Vector, timestamp);
            assert_eq!(events.len(), 1);

            let event = events[0].as_log();
            assert_eq!(event.get("host").unwrap(), &Value::from("server01"));
            assert_eq!(event.get("message").unwrap(), &Value::from("hello"));
            assert_eq!(event.get("severity").unwrap(), &Value::from("info"));
        }
    }

    #[test]
    fn deserialize_csv_streaming_header_then_data() {
        let deserializer = CsvDeserializerConfig::default().build();
        let timestamp = Utc::now();

        {
            let mut state = deserializer.state.lock().unwrap();
            let events =
                CsvDeserializer::process_bytes(&mut state, b"host,message\n", LogNamespace::Vector, timestamp);
            assert!(events.is_empty());
            assert_eq!(
                state.headers.as_ref().unwrap(),
                &vec!["host".to_string(), "message".to_string()]
            );
        }

        {
            let mut state = deserializer.state.lock().unwrap();
            let events =
                CsvDeserializer::process_bytes(&mut state, b"server01,hello\n", LogNamespace::Vector, timestamp);
            assert_eq!(events.len(), 1);
            let event = events[0].as_log();
            assert_eq!(event.get("host").unwrap(), &Value::from("server01"));
            assert_eq!(event.get("message").unwrap(), &Value::from("hello"));
        }
    }

    #[test]
    fn deserialize_csv_streaming_multiline_field_split() {
        let config = CsvDeserializerConfig {
            csv: CsvDeserializerOptions {
                headers: Some(vec!["host".to_string(), "message".to_string()]),
                ..Default::default()
            },
        };
        let deserializer = config.build();
        let timestamp = Utc::now();

        {
            let mut state = deserializer.state.lock().unwrap();
            let events = CsvDeserializer::process_bytes(
                &mut state,
                b"server01,\"line1\nli",
                LogNamespace::Vector,
                timestamp,
            );
            assert!(events.is_empty());
        }

        {
            let mut state = deserializer.state.lock().unwrap();
            let events = CsvDeserializer::process_bytes(
                &mut state,
                b"ne2\"\n",
                LogNamespace::Vector,
                timestamp,
            );
            assert_eq!(events.len(), 1);
            let event = events[0].as_log();
            assert_eq!(event.get("host").unwrap(), &Value::from("server01"));
            assert_eq!(
                event.get("message").unwrap(),
                &Value::from("line1\nline2")
            );
        }
    }

    // ── Byte-at-a-time tests ────────────────────────────────────────────

    #[test]
    fn deserialize_csv_streaming_one_byte_at_a_time() {
        let csv_data = b"host,message,severity\n\
                         server01,\"line 1\nline 2\",warning\n\
                         server02,\"has \"\"quotes\"\"\",info\n\
                         server03,\"comma,inside\",error\n";

        let deserializer = CsvDeserializerConfig::default().build();
        let timestamp = Utc::now();

        let mut all_events = SmallVec::<[Event; 1]>::new();
        {
            let mut state = deserializer.state.lock().unwrap();
            for &byte in csv_data.iter() {
                let events = CsvDeserializer::process_bytes(
                    &mut state,
                    &[byte],
                    LogNamespace::Vector,
                    timestamp,
                );
                all_events.extend(events);
            }
        }

        assert_eq!(all_events.len(), 3);

        let e1 = all_events[0].as_log();
        assert_eq!(e1.get("host").unwrap(), &Value::from("server01"));
        assert_eq!(e1.get("message").unwrap(), &Value::from("line 1\nline 2"));
        assert_eq!(e1.get("severity").unwrap(), &Value::from("warning"));

        let e2 = all_events[1].as_log();
        assert_eq!(e2.get("host").unwrap(), &Value::from("server02"));
        assert_eq!(e2.get("message").unwrap(), &Value::from("has \"quotes\""));
        assert_eq!(e2.get("severity").unwrap(), &Value::from("info"));

        let e3 = all_events[2].as_log();
        assert_eq!(e3.get("host").unwrap(), &Value::from("server03"));
        assert_eq!(e3.get("message").unwrap(), &Value::from("comma,inside"));
        assert_eq!(e3.get("severity").unwrap(), &Value::from("error"));
    }

    #[test]
    fn deserialize_csv_streaming_one_byte_no_trailing_newline() {
        let csv_data = b"a,b\n1,\"multi\nline\"";

        let deserializer = CsvDeserializerConfig::default().build();
        let timestamp = Utc::now();

        let mut all_events = SmallVec::<[Event; 1]>::new();
        {
            let mut state = deserializer.state.lock().unwrap();
            for &byte in csv_data.iter() {
                all_events.extend(CsvDeserializer::process_bytes(
                    &mut state,
                    &[byte],
                    LogNamespace::Vector,
                    timestamp,
                ));
            }
        }

        // No trailing \n — last record stays buffered
        assert_eq!(all_events.len(), 0);

        // parse() signals EOF and flushes
        let deserializer2 = CsvDeserializerConfig::default().build();
        let events = deserializer2
            .parse(Bytes::copy_from_slice(csv_data), LogNamespace::Vector)
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].as_log().get("a").unwrap(), &Value::from("1"));
        assert_eq!(
            events[0].as_log().get("b").unwrap(),
            &Value::from("multi\nline")
        );
    }

    #[test]
    fn deserialize_csv_streaming_one_byte_no_headers() {
        let csv_data = b"hello,\"world\nnewline\",test\n";

        let config = CsvDeserializerConfig {
            csv: CsvDeserializerOptions {
                has_header: Some(false),
                ..Default::default()
            },
        };
        let deserializer = config.build();
        let timestamp = Utc::now();

        let mut all_events = SmallVec::<[Event; 1]>::new();
        {
            let mut state = deserializer.state.lock().unwrap();
            for &byte in csv_data.iter() {
                all_events.extend(CsvDeserializer::process_bytes(
                    &mut state,
                    &[byte],
                    LogNamespace::Vector,
                    timestamp,
                ));
            }
        }

        assert_eq!(all_events.len(), 1);
        assert_eq!(
            all_events[0].as_log().get("message").unwrap(),
            &Value::Array(vec![
                Value::from("hello"),
                Value::from("world\nnewline"),
                Value::from("test"),
            ])
        );
    }

    // ── Negative tests ──────────────────────────────────────────────────

    #[test]
    fn deserialize_csv_variable_field_counts() {
        let input = Bytes::from("a,b,c\n1,2,3\n4,5");
        let deserializer = CsvDeserializerConfig::default().build();

        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();
        assert_eq!(events.len(), 2);

        let event2 = events[1].as_log();
        assert_eq!(event2.get("a").unwrap(), &Value::from("4"));
        assert_eq!(event2.get("b").unwrap(), &Value::from("5"));
        assert!(event2.get("c").is_none());
    }

    #[test]
    fn deserialize_csv_unclosed_quote_is_lenient() {
        let input = Bytes::from("host,message\nserver01,\"unterminated field");
        let deserializer = CsvDeserializerConfig::default().build();

        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();
        assert_eq!(events.len(), 1);

        let event = events[0].as_log();
        assert_eq!(event.get("host").unwrap(), &Value::from("server01"));
        assert_eq!(
            event.get("message").unwrap(),
            &Value::from("unterminated field")
        );
    }

    #[test]
    fn deserialize_csv_header_only_no_events() {
        let input = Bytes::from("host,message,severity");
        let deserializer = CsvDeserializerConfig::default().build();

        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn newline_framing_csv_decoder_multiline_fields_fails() {
        use crate::actions::Decoder;
        use crate::decoding::{Deserializer as DeserializerEnum, Framer};
        use crate::NewlineDelimitedDecoder;
        use bytes::Bytes;
        use futures::{stream, StreamExt};
        use tokio_util::{codec::FramedRead, io::StreamReader};

        let csv_data =
            "host,message,severity\nserver01,\"multi\nline\nlog\",warning\nserver02,ok,info";

        let iter = stream::iter([csv_data].into_iter().map(Bytes::from));
        let stream = iter.map(Ok::<_, std::io::Error>);
        let reader = StreamReader::new(stream);

        let csv_deserializer = CsvDeserializerConfig {
            csv: CsvDeserializerOptions {
                headers: Some(vec![
                    "host".to_string(),
                    "message".to_string(),
                    "severity".to_string(),
                ]),
                ..Default::default()
            },
        }
        .build();

        let decoder = Decoder::new(
            Framer::NewlineDelimited(NewlineDelimitedDecoder::new()),
            DeserializerEnum::Csv(csv_deserializer),
        );
        let mut stream = FramedRead::new(reader, decoder);

        // Frame 1: "host,message,severity" — treated as data row
        let next = stream.next().await.unwrap();
        let events = next.unwrap().0;
        assert_eq!(events.len(), 1);

        // Frame 2: 'server01,"multi' — truncated, field is mangled
        let next = stream.next().await.unwrap();
        let events = next.unwrap().0;
        assert_eq!(events.len(), 1);
        let msg = events[0].as_log().get("message").unwrap().to_string_lossy();
        assert!(!msg.contains("line\nlog"));

        // Frame 3: "line" — fragment
        let next = stream.next().await.unwrap();
        let events = next.unwrap().0;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].as_log().get("host").unwrap(), &Value::from("line"));
    }

    #[test]
    fn deserialize_csv_binary_garbage() {
        let input = Bytes::from(vec![0xFF, 0xFE, 0x00, 0x01, 0x0A, 0xFF]);
        let config = CsvDeserializerConfig {
            csv: CsvDeserializerOptions {
                has_header: Some(false),
                ..Default::default()
            },
        };
        let deserializer = config.build();
        let _ = deserializer.parse(input, LogNamespace::Vector);
    }

    #[test]
    fn deserialize_csv_extra_fields_get_fallback_names() {
        let input = Bytes::from("a,b\n1,2,3");
        let deserializer = CsvDeserializerConfig::default().build();

        let events = deserializer.parse(input, LogNamespace::Vector).unwrap();
        assert_eq!(events.len(), 1);

        let event = events[0].as_log();
        assert_eq!(event.get("a").unwrap(), &Value::from("1"));
        assert_eq!(event.get("b").unwrap(), &Value::from("2"));
        assert_eq!(event.get("column_2").unwrap(), &Value::from("3"));
    }
}
