use std::{io, sync::Arc};

use bytes::BytesMut;
use itertools::{Itertools, Position};
use tokio_util::codec::Encoder as _;
use vector_lib::codecs::encoding::Framer;
use vector_lib::request_metadata::GroupedCountByteSize;
use vector_lib::{config::telemetry, EstimatedJsonEncodedSizeOf};

use crate::{
    codecs::Transformer,
    event::Event,
    internal_events::EncoderWriteError,
};

pub trait Encoder<T> {
    /// Encodes the input into the provided writer.
    ///
    /// # Errors
    ///
    /// If an I/O error is encountered while encoding the input, an error variant will be returned.
    fn encode_input(
        &self,
        input: T,
        writer: &mut dyn io::Write,
    ) -> io::Result<(usize, GroupedCountByteSize)>;
}

impl Encoder<Vec<Event>> for (Transformer, crate::codecs::Encoder<Framer>) {
    fn encode_input(
        &self,
        events: Vec<Event>,
        writer: &mut dyn io::Write,
    ) -> io::Result<(usize, GroupedCountByteSize)> {
        let mut encoder = self.1.clone();
        let mut bytes_written = 0;
        let mut n_events_pending = events.len();
        let batch_prefix = encoder.batch_prefix();
        write_all(writer, n_events_pending, batch_prefix)?;
        bytes_written += batch_prefix.len();

        let mut byte_size = telemetry().create_request_count_byte_size();

        for (position, mut event) in events.into_iter().with_position() {
            self.0.transform(&mut event);

            // Ensure the json size is calculated after any fields have been removed
            // by the transformer.
            byte_size.add_event(&event, event.estimated_json_encoded_size_of());

            let mut bytes = BytesMut::new();
            match position {
                Position::Last | Position::Only => {
                    encoder
                        .serialize(event, &mut bytes)
                        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                }
                _ => {
                    encoder
                        .encode(event, &mut bytes)
                        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                }
            }
            write_all(writer, n_events_pending, &bytes)?;
            bytes_written += bytes.len();
            n_events_pending -= 1;
        }

        let batch_suffix = encoder.batch_suffix();
        assert!(n_events_pending == 0);
        write_all(writer, 0, batch_suffix)?;
        bytes_written += batch_suffix.len();

        Ok((bytes_written, byte_size))
    }
}

impl Encoder<Event> for (Transformer, crate::codecs::Encoder<()>) {
    fn encode_input(
        &self,
        mut event: Event,
        writer: &mut dyn io::Write,
    ) -> io::Result<(usize, GroupedCountByteSize)> {
        let mut encoder = self.1.clone();
        self.0.transform(&mut event);

        let mut byte_size = telemetry().create_request_count_byte_size();
        byte_size.add_event(&event, event.estimated_json_encoded_size_of());

        let mut bytes = BytesMut::new();
        encoder
            .serialize(event, &mut bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        write_all(writer, 1, &bytes)?;
        Ok((bytes.len(), byte_size))
    }
}

impl<T, D: Encoder<T> + ?Sized> Encoder<T> for Arc<D> {
    fn encode_input(&self, input: T, writer: &mut dyn io::Write) -> io::Result<(usize, GroupedCountByteSize)> {
        (**self).encode_input(input, writer)
    }
}

impl Encoder<Vec<Event>> for (Transformer, vector_lib::codecs::encoding::BatchEncoder) {
    fn encode_input(
        &self,
        mut events: Vec<Event>,
        writer: &mut dyn io::Write,
    ) -> io::Result<(usize, GroupedCountByteSize)> {
        let mut encoder = self.1.clone();
        let n_events_pending = events.len();

        let mut byte_size = telemetry().create_request_count_byte_size();
        for event in &mut events {
            self.0.transform(event);
            byte_size.add_event(event, event.estimated_json_encoded_size_of());
        }

        let mut bytes = BytesMut::new();
        encoder.encode(events, &mut bytes).map_err(|error| {
            // Do NOT emit internal events here — the codec layer
            // (`Encoder<Framer>::serialize_at_start` / `encode`) already emits
            // `EncoderSerializeError` or `EncoderFramingError` as appropriate.
            io::Error::new(io::ErrorKind::InvalidData, error)
        })?;

        write_all(writer, n_events_pending, &bytes)?;
        let num_bytes = bytes.len();

        Ok((num_bytes, byte_size))
    }
}

/// Write the buffer to the writer. If the operation fails, emit an internal event which complies with the
/// instrumentation spec- as this necessitates both an Error and EventsDropped event.
///
/// # Arguments
///
/// * `writer`           - The object implementing io::Write to write data to.
/// * `n_events_pending` - The number of events that are dropped if this write fails.
/// * `buf`              - The buffer to write.
pub fn write_all(
    writer: &mut dyn io::Write,
    n_events_pending: usize,
    buf: &[u8],
) -> io::Result<()> {
    writer.write_all(buf).inspect_err(|error| {
        emit!(EncoderWriteError {
            error,
            count: n_events_pending,
        });
    })
}

pub fn as_tracked_write<F, I, E>(inner: &mut dyn io::Write, input: I, f: F) -> io::Result<usize>
where
    F: FnOnce(&mut dyn io::Write, I) -> Result<(), E>,
    E: Into<io::Error> + 'static,
{
    struct Tracked<'inner> {
        count: usize,
        inner: &'inner mut dyn io::Write,
    }

    impl io::Write for Tracked<'_> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            #[allow(clippy::disallowed_methods)] // We pass on the result of `write` to the caller.
            let n = self.inner.write(buf)?;
            self.count += n;
            Ok(n)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }

    let mut tracked = Tracked { count: 0, inner };
    f(&mut tracked, input).map_err(|e| e.into())?;
    Ok(tracked.count)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use vector_lib::codecs::{
        CharacterDelimitedEncoder, JsonSerializerConfig, NewlineDelimitedEncoder,
        TextSerializerConfig,
    };
    use vector_lib::event::LogEvent;
    use vector_lib::{internal_event::CountByteSize, json_size::JsonSize};
    use vrl::value::{KeyString, Value};

    use super::*;

    #[test]
    fn test_encode_batch_json_empty() {
        let encoding = (
            Transformer::default(),
            crate::codecs::Encoder::<Framer>::new(
                CharacterDelimitedEncoder::new(b',').into(),
                JsonSerializerConfig::default().build().into(),
            ),
        );

        let mut writer = Vec::new();
        let (written, json_size) = encoding.encode_input(vec![], &mut writer).unwrap();
        assert_eq!(written, 2);

        assert_eq!(String::from_utf8(writer).unwrap(), "[]");
        assert_eq!(
            CountByteSize(0, JsonSize::zero()),
            json_size.size().unwrap()
        );
    }

    #[test]
    fn test_encode_batch_json_single() {
        let encoding = (
            Transformer::default(),
            crate::codecs::Encoder::<Framer>::new(
                CharacterDelimitedEncoder::new(b',').into(),
                JsonSerializerConfig::default().build().into(),
            ),
        );

        let mut writer = Vec::new();
        let input = vec![Event::Log(LogEvent::from(BTreeMap::from([(
            KeyString::from("key"),
            Value::from("value"),
        )])))];

        let input_json_size = input
            .iter()
            .map(|event| event.estimated_json_encoded_size_of())
            .sum::<JsonSize>();

        let (written, json_size) = encoding.encode_input(input, &mut writer).unwrap();
        assert_eq!(written, 17);

        assert_eq!(String::from_utf8(writer).unwrap(), r#"[{"key":"value"}]"#);
        assert_eq!(CountByteSize(1, input_json_size), json_size.size().unwrap());
    }

    #[test]
    fn test_encode_batch_json_multiple() {
        let encoding = (
            Transformer::default(),
            crate::codecs::Encoder::<Framer>::new(
                CharacterDelimitedEncoder::new(b',').into(),
                JsonSerializerConfig::default().build().into(),
            ),
        );

        let input = vec![
            Event::Log(LogEvent::from(BTreeMap::from([(
                KeyString::from("key"),
                Value::from("value1"),
            )]))),
            Event::Log(LogEvent::from(BTreeMap::from([(
                KeyString::from("key"),
                Value::from("value2"),
            )]))),
            Event::Log(LogEvent::from(BTreeMap::from([(
                KeyString::from("key"),
                Value::from("value3"),
            )]))),
        ];

        let input_json_size = input
            .iter()
            .map(|event| event.estimated_json_encoded_size_of())
            .sum::<JsonSize>();

        let mut writer = Vec::new();
        let (written, json_size) = encoding.encode_input(input, &mut writer).unwrap();
        assert_eq!(written, 52);

        assert_eq!(
            String::from_utf8(writer).unwrap(),
            r#"[{"key":"value1"},{"key":"value2"},{"key":"value3"}]"#
        );

        assert_eq!(CountByteSize(3, input_json_size), json_size.size().unwrap());
    }

    #[test]
    fn test_encode_batch_ndjson_empty() {
        let encoding = (
            Transformer::default(),
            crate::codecs::Encoder::<Framer>::new(
                NewlineDelimitedEncoder::default().into(),
                JsonSerializerConfig::default().build().into(),
            ),
        );

        let mut writer = Vec::new();
        let (written, json_size) = encoding.encode_input(vec![], &mut writer).unwrap();
        assert_eq!(written, 0);

        assert_eq!(String::from_utf8(writer).unwrap(), "");
        assert_eq!(
            CountByteSize(0, JsonSize::zero()),
            json_size.size().unwrap()
        );
    }

    #[test]
    fn test_encode_batch_ndjson_single() {
        let encoding = (
            Transformer::default(),
            crate::codecs::Encoder::<Framer>::new(
                NewlineDelimitedEncoder::default().into(),
                JsonSerializerConfig::default().build().into(),
            ),
        );

        let mut writer = Vec::new();
        let input = vec![Event::Log(LogEvent::from(BTreeMap::from([(
            KeyString::from("key"),
            Value::from("value"),
        )])))];
        let input_json_size = input
            .iter()
            .map(|event| event.estimated_json_encoded_size_of())
            .sum::<JsonSize>();

        let (written, json_size) = encoding.encode_input(input, &mut writer).unwrap();
        assert_eq!(written, 15);

        assert_eq!(String::from_utf8(writer).unwrap(), r#"{"key":"value"}"#);
        assert_eq!(CountByteSize(1, input_json_size), json_size.size().unwrap());
    }

    #[test]
    fn test_encode_batch_ndjson_multiple() {
        let encoding = (
            Transformer::default(),
            crate::codecs::Encoder::<Framer>::new(
                NewlineDelimitedEncoder::default().into(),
                JsonSerializerConfig::default().build().into(),
            ),
        );

        let mut writer = Vec::new();
        let input = vec![
            Event::Log(LogEvent::from(BTreeMap::from([(
                KeyString::from("key"),
                Value::from("value1"),
            )]))),
            Event::Log(LogEvent::from(BTreeMap::from([(
                KeyString::from("key"),
                Value::from("value2"),
            )]))),
            Event::Log(LogEvent::from(BTreeMap::from([(
                KeyString::from("key"),
                Value::from("value3"),
            )]))),
        ];
        let input_json_size = input
            .iter()
            .map(|event| event.estimated_json_encoded_size_of())
            .sum::<JsonSize>();

        let (written, json_size) = encoding.encode_input(input, &mut writer).unwrap();
        assert_eq!(written, 50);

        assert_eq!(
            String::from_utf8(writer).unwrap(),
            "{\"key\":\"value1\"}\n{\"key\":\"value2\"}\n{\"key\":\"value3\"}"
        );
        assert_eq!(CountByteSize(3, input_json_size), json_size.size().unwrap());
    }

    #[test]
    fn test_encode_event_json() {
        let encoding = (
            Transformer::default(),
            crate::codecs::Encoder::<()>::new(JsonSerializerConfig::default().build().into()),
        );

        let mut writer = Vec::new();
        let input = Event::Log(LogEvent::from(BTreeMap::from([(
            KeyString::from("key"),
            Value::from("value"),
        )])));
        let input_json_size = input.estimated_json_encoded_size_of();

        let (written, json_size) = encoding.encode_input(input, &mut writer).unwrap();
        assert_eq!(written, 15);

        assert_eq!(String::from_utf8(writer).unwrap(), r#"{"key":"value"}"#);
        assert_eq!(CountByteSize(1, input_json_size), json_size.size().unwrap());
    }

    #[test]
    fn test_encode_event_text() {
        let encoding = (
            Transformer::default(),
            crate::codecs::Encoder::<()>::new(TextSerializerConfig::default().build().into()),
        );

        let mut writer = Vec::new();
        let input = Event::Log(LogEvent::from(BTreeMap::from([(
            KeyString::from("message"),
            Value::from("value"),
        )])));
        let input_json_size = input.estimated_json_encoded_size_of();

        let (written, json_size) = encoding.encode_input(input, &mut writer).unwrap();
        assert_eq!(written, 5);

        assert_eq!(String::from_utf8(writer).unwrap(), r"value");
        assert_eq!(CountByteSize(1, input_json_size), json_size.size().unwrap());
    }

    // ---- Helper to build a (Transformer, BatchEncoder) from common params ----

    use vector_lib::codecs::encoding::{
        BatchEncodingConfig, BatchSerializerConfig, EventEncodingConfig, FramingConfig,
        SerializerConfig, CharacterDelimitedEncoderConfig,
    };

    fn build_batch_encoder(
        framing: FramingConfig,
        serializer: SerializerConfig,
    ) -> (Transformer, vector_lib::codecs::encoding::BatchEncoder) {
        let cfg = BatchEncodingConfig {
            framing: None, // auto-detect
            encoding: BatchSerializerConfig::Stack(EventEncodingConfig {
                framing: Some(framing),
                serializer,
            }),
            transformer: Transformer::default(),
        };
        let (encoder, transformer) = cfg.build().expect("build");
        (transformer, encoder)
    }

    fn build_batch_encoder_with_transformer(
        framing: FramingConfig,
        serializer: SerializerConfig,
        transformer: Transformer,
    ) -> (Transformer, vector_lib::codecs::encoding::BatchEncoder) {
        let cfg = BatchEncodingConfig {
            framing: None,
            encoding: BatchSerializerConfig::Stack(EventEncodingConfig {
                framing: Some(framing),
                serializer,
            }),
            transformer,
        };
        let (encoder, t) = cfg.build().expect("build");
        (t, encoder)
    }

    fn mk_log_event(pairs: &[(&str, &str)]) -> Event {
        Event::Log(LogEvent::from(BTreeMap::from_iter(
            pairs
                .iter()
                .map(|(k, v)| (KeyString::from(*k), Value::from(*v))),
        )))
    }

    #[test]
    fn test_batch_encoder_vs_old_encoder_ndjson_parity() {
        // Old encoder: (Transformer, Encoder<Framer>)
        let old = (
            Transformer::default(),
            crate::codecs::Encoder::<Framer>::new(
                NewlineDelimitedEncoder::default().into(),
                JsonSerializerConfig::default().build().into(),
            ),
        );

        // New encoder: (Transformer, BatchEncoder)
        let new = build_batch_encoder(
            FramingConfig::NewlineDelimited,
            SerializerConfig::Json(JsonSerializerConfig::default()),
        );

        let events = vec![
            mk_log_event(&[("key", "value1")]),
            mk_log_event(&[("key", "value2")]),
            mk_log_event(&[("key", "value3")]),
        ];

        let mut old_buf = Vec::new();
        let (old_written, old_json_size) = old.encode_input(events.clone(), &mut old_buf).unwrap();

        let mut new_buf = Vec::new();
        let (new_written, new_json_size) = new.encode_input(events, &mut new_buf).unwrap();

        assert_eq!(
            old_buf, new_buf,
            "ndjson parity: old={}, new={}",
            String::from_utf8_lossy(&old_buf),
            String::from_utf8_lossy(&new_buf),
        );
        assert_eq!(old_written, new_written, "byte count must match");
        assert_eq!(
            old_json_size.size().unwrap(),
            new_json_size.size().unwrap(),
            "json size must match"
        );
    }

    #[test]
    fn test_batch_encoder_vs_old_encoder_comma_json_parity() {
        let old = (
            Transformer::default(),
            crate::codecs::Encoder::<Framer>::new(
                CharacterDelimitedEncoder::new(b',').into(),
                JsonSerializerConfig::default().build().into(),
            ),
        );

        let new = build_batch_encoder(
            FramingConfig::CharacterDelimited(CharacterDelimitedEncoderConfig::new(b',')),
            SerializerConfig::Json(JsonSerializerConfig::default()),
        );

        let events = vec![
            mk_log_event(&[("key", "value1")]),
            mk_log_event(&[("key", "value2")]),
            mk_log_event(&[("key", "value3")]),
        ];

        let mut old_buf = Vec::new();
        let (old_written, old_json_size) = old.encode_input(events.clone(), &mut old_buf).unwrap();

        let mut new_buf = Vec::new();
        let (new_written, new_json_size) = new.encode_input(events, &mut new_buf).unwrap();

        assert_eq!(
            old_buf, new_buf,
            "comma-json parity: old={}, new={}",
            String::from_utf8_lossy(&old_buf),
            String::from_utf8_lossy(&new_buf),
        );
        assert_eq!(old_written, new_written, "byte count must match");
        assert_eq!(
            old_json_size.size().unwrap(),
            new_json_size.size().unwrap(),
            "json size must match"
        );
        // Verify it's a valid JSON array
        let output = String::from_utf8(new_buf).unwrap();
        assert!(output.starts_with('[') && output.ends_with(']'), "must be JSON array: {output}");
    }

    #[test]
    fn test_batch_encoder_vs_old_encoder_text_newline_parity() {
        let old = (
            Transformer::default(),
            crate::codecs::Encoder::<Framer>::new(
                NewlineDelimitedEncoder::default().into(),
                TextSerializerConfig::default().build().into(),
            ),
        );

        let new = build_batch_encoder(
            FramingConfig::NewlineDelimited,
            SerializerConfig::Text(TextSerializerConfig::default()),
        );

        let events = vec![
            mk_log_event(&[("message", "hello")]),
            mk_log_event(&[("message", "world")]),
            mk_log_event(&[("message", "test")]),
        ];

        let mut old_buf = Vec::new();
        let (old_written, old_json_size) = old.encode_input(events.clone(), &mut old_buf).unwrap();

        let mut new_buf = Vec::new();
        let (new_written, new_json_size) = new.encode_input(events, &mut new_buf).unwrap();

        assert_eq!(
            old_buf, new_buf,
            "text+newline parity: old={}, new={}",
            String::from_utf8_lossy(&old_buf),
            String::from_utf8_lossy(&new_buf),
        );
        assert_eq!(old_written, new_written, "byte count must match");
        assert_eq!(
            old_json_size.size().unwrap(),
            new_json_size.size().unwrap(),
            "json size must match"
        );
    }

    // Parity for edge cases: empty batch and single event

    #[test]
    fn test_batch_encoder_vs_old_encoder_ndjson_empty_parity() {
        let old = (
            Transformer::default(),
            crate::codecs::Encoder::<Framer>::new(
                NewlineDelimitedEncoder::default().into(),
                JsonSerializerConfig::default().build().into(),
            ),
        );
        let new = build_batch_encoder(
            FramingConfig::NewlineDelimited,
            SerializerConfig::Json(JsonSerializerConfig::default()),
        );

        let mut old_buf = Vec::new();
        let (old_written, old_json_size) = old.encode_input(vec![], &mut old_buf).unwrap();
        let mut new_buf = Vec::new();
        let (new_written, new_json_size) = new.encode_input(vec![], &mut new_buf).unwrap();

        assert_eq!(old_buf, new_buf, "empty ndjson parity");
        assert_eq!(old_written, new_written);
        assert_eq!(
            old_json_size.size().unwrap(),
            new_json_size.size().unwrap(),
            "json size must match for empty batch"
        );
    }

    #[test]
    fn test_batch_encoder_vs_old_encoder_comma_json_empty_parity() {
        let old = (
            Transformer::default(),
            crate::codecs::Encoder::<Framer>::new(
                CharacterDelimitedEncoder::new(b',').into(),
                JsonSerializerConfig::default().build().into(),
            ),
        );
        let new = build_batch_encoder(
            FramingConfig::CharacterDelimited(CharacterDelimitedEncoderConfig::new(b',')),
            SerializerConfig::Json(JsonSerializerConfig::default()),
        );

        let mut old_buf = Vec::new();
        let (old_written, old_json_size) = old.encode_input(vec![], &mut old_buf).unwrap();
        let mut new_buf = Vec::new();
        let (new_written, new_json_size) = new.encode_input(vec![], &mut new_buf).unwrap();

        assert_eq!(old_buf, new_buf, "empty comma-json parity");
        assert_eq!(old_written, new_written);
        assert_eq!(String::from_utf8(new_buf).unwrap(), "[]");
        assert_eq!(
            old_json_size.size().unwrap(),
            new_json_size.size().unwrap(),
            "json size must match for empty batch"
        );
    }

    #[test]
    fn test_batch_encoder_vs_old_encoder_single_event_parity() {
        let old = (
            Transformer::default(),
            crate::codecs::Encoder::<Framer>::new(
                CharacterDelimitedEncoder::new(b',').into(),
                JsonSerializerConfig::default().build().into(),
            ),
        );
        let new = build_batch_encoder(
            FramingConfig::CharacterDelimited(CharacterDelimitedEncoderConfig::new(b',')),
            SerializerConfig::Json(JsonSerializerConfig::default()),
        );

        let events = vec![mk_log_event(&[("key", "only")])];

        let mut old_buf = Vec::new();
        let (old_written, old_json_size) = old.encode_input(events.clone(), &mut old_buf).unwrap();
        let mut new_buf = Vec::new();
        let (new_written, new_json_size) = new.encode_input(events, &mut new_buf).unwrap();

        assert_eq!(
            old_buf, new_buf,
            "single-event comma-json parity: old={}, new={}",
            String::from_utf8_lossy(&old_buf),
            String::from_utf8_lossy(&new_buf),
        );
        assert_eq!(old_written, new_written);
        assert_eq!(
            old_json_size.size().unwrap(),
            new_json_size.size().unwrap(),
            "json size must match for single event"
        );
    }

    #[test]
    fn test_batch_encoder_returns_correct_byte_count() {
        let encoding = build_batch_encoder(
            FramingConfig::CharacterDelimited(CharacterDelimitedEncoderConfig::new(b',')),
            SerializerConfig::Json(JsonSerializerConfig::default()),
        );

        let events = vec![
            mk_log_event(&[("a", "1")]),
            mk_log_event(&[("a", "2")]),
        ];

        let mut writer = Vec::new();
        let (written, _) = encoding.encode_input(events, &mut writer).unwrap();

        assert_eq!(
            written,
            writer.len(),
            "returned byte count must match actual bytes written"
        );
    }

    #[test]
    fn test_batch_encoder_transformer_except_fields() {
        let transformer = Transformer::new(
            None,
            Some(vec!["drop_me".into()]),
            None,
            BTreeMap::new(),
        )
        .unwrap();

        let encoding = build_batch_encoder_with_transformer(
            FramingConfig::NewlineDelimited,
            SerializerConfig::Json(JsonSerializerConfig::default()),
            transformer,
        );

        let events = vec![
            mk_log_event(&[("keep", "yes"), ("drop_me", "secret")]),
            mk_log_event(&[("keep", "also"), ("drop_me", "hidden")]),
        ];

        let mut writer = Vec::new();
        encoding.encode_input(events, &mut writer).unwrap();
        let output = String::from_utf8(writer).unwrap();

        assert!(
            !output.contains("drop_me"),
            "transformer must remove except_fields, got: {output}"
        );
        assert!(
            !output.contains("secret"),
            "field value must be removed, got: {output}"
        );
        assert!(output.contains("keep"), "non-excluded fields must remain: {output}");
    }

    #[test]
    fn test_batch_encoder_transformer_except_fields_parity() {
        // Verify the new encoder matches the old encoder when using except_fields.
        let transformer = Transformer::new(
            None,
            Some(vec!["drop_me".into()]),
            None,
            BTreeMap::new(),
        )
        .unwrap();

        let old = (
            transformer.clone(),
            crate::codecs::Encoder::<Framer>::new(
                NewlineDelimitedEncoder::default().into(),
                JsonSerializerConfig::default().build().into(),
            ),
        );
        let new = build_batch_encoder_with_transformer(
            FramingConfig::NewlineDelimited,
            SerializerConfig::Json(JsonSerializerConfig::default()),
            transformer,
        );

        let events = vec![
            mk_log_event(&[("keep", "yes"), ("drop_me", "secret")]),
            mk_log_event(&[("keep", "also"), ("drop_me", "hidden")]),
        ];

        let mut old_buf = Vec::new();
        let (_, old_json_size) = old.encode_input(events.clone(), &mut old_buf).unwrap();
        let mut new_buf = Vec::new();
        let (_, new_json_size) = new.encode_input(events, &mut new_buf).unwrap();

        assert_eq!(
            old_buf, new_buf,
            "except_fields parity: old={}, new={}",
            String::from_utf8_lossy(&old_buf),
            String::from_utf8_lossy(&new_buf),
        );
        assert_eq!(
            old_json_size.size().unwrap(),
            new_json_size.size().unwrap(),
            "json size must match with except_fields transformer"
        );
    }

    #[test]
    fn test_batch_encoder_transformer_timestamp_format() {
        use crate::codecs::TimestampFormat;
        use chrono::{TimeZone, Utc};
        use vector_lib::event::Event;

        let transformer = Transformer::new(
            None,
            None,
            Some(TimestampFormat::Unix),
            BTreeMap::new(),
        )
        .unwrap();

        let encoding = build_batch_encoder_with_transformer(
            FramingConfig::NewlineDelimited,
            SerializerConfig::Json(JsonSerializerConfig::default()),
            transformer,
        );

        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let mut log = LogEvent::default();
        log.insert("message", "hello");
        log.insert("timestamp", ts);
        let events = vec![Event::Log(log)];

        let mut writer = Vec::new();
        encoding.encode_input(events, &mut writer).unwrap();
        let output = String::from_utf8(writer).unwrap();

        // Unix timestamp format should produce a numeric timestamp, not an ISO 8601 string
        assert!(
            !output.contains("2025-06-15"),
            "unix timestamp_format must not produce ISO date: {output}"
        );
    }

    #[test]
    fn test_batch_encoder_ndjson_content_type() {
        let (encoder, _) = BatchEncodingConfig {
            framing: None,
            encoding: BatchSerializerConfig::Stack(EventEncodingConfig {
                framing: Some(FramingConfig::NewlineDelimited),
                serializer: SerializerConfig::Json(JsonSerializerConfig::default()),
            }),
            transformer: Transformer::default(),
        }
        .build()
        .unwrap();

        assert_eq!(encoder.content_type(), "application/x-ndjson");
    }

    #[test]
    fn test_batch_encoder_comma_json_content_type() {
        let (encoder, _) = BatchEncodingConfig {
            framing: None,
            encoding: BatchSerializerConfig::Stack(EventEncodingConfig {
                framing: Some(FramingConfig::CharacterDelimited(
                    CharacterDelimitedEncoderConfig::new(b','),
                )),
                serializer: SerializerConfig::Json(JsonSerializerConfig::default()),
            }),
            transformer: Transformer::default(),
        }
        .build()
        .unwrap();

        assert_eq!(encoder.content_type(), "application/json");
    }

    #[test]
    fn test_batch_encoder_text_content_type() {
        let (encoder, _) = BatchEncodingConfig {
            framing: None,
            encoding: BatchSerializerConfig::Stack(EventEncodingConfig {
                framing: Some(FramingConfig::NewlineDelimited),
                serializer: SerializerConfig::Text(TextSerializerConfig::default()),
            }),
            transformer: Transformer::default(),
        }
        .build()
        .unwrap();

        assert_eq!(encoder.content_type(), "text/plain");
    }

    #[test]
    fn test_batch_encoder_serialization_error_emits_single_internal_event() {
        // GELF requires 'host' and 'message'/'short_message'. An empty LogEvent
        // will fail serialization. We verify that `component_errors_total` is
        // emitted exactly once (not double-emitted by both codec and sink layers).
        use crate::event::metric::MetricValue;
        use crate::metrics::Controller;

        vector_lib::metrics::init_test();

        let encoding = build_batch_encoder(
            FramingConfig::NewlineDelimited,
            SerializerConfig::Gelf,
        );

        let events = vec![mk_log_event(&[("unrelated", "field")])]; // missing 'host'

        let mut writer = Vec::new();
        let result = encoding.encode_input(events, &mut writer);
        assert!(result.is_err(), "GELF without required fields must error");

        let controller = Controller::get().expect("no controller");
        let metrics = controller.capture_metrics();

        let error_count: f64 = metrics
            .iter()
            .filter(|m| {
                m.name() == "component_errors_total"
                    && m.tag_value("error_code").as_deref() == Some("encoder_serialize")
            })
            .filter_map(|m| match m.value() {
                MetricValue::Counter { value } => Some(*value),
                _ => None,
            })
            .sum();

        assert_eq!(
            error_count, 1.0,
            "component_errors_total with error_code=encoder_serialize must be emitted exactly once"
        );
    }

    #[test]
    fn test_batch_encoder_all_or_nothing_on_error() {
        // When the 2nd event fails serialization, the writer should receive 0 bytes
        // because the BatchEncoder serializes into an internal buffer first, then writes.
        let encoding = build_batch_encoder(
            FramingConfig::NewlineDelimited,
            SerializerConfig::Gelf,
        );

        // First event has required GELF fields, second does not.
        // GELF requires 'host' and 'message' (or 'short_message').
        let good_event = mk_log_event(&[("host", "myhost"), ("message", "hello")]);
        let bad_event = mk_log_event(&[("unrelated", "field")]); // missing 'host'

        let events = vec![good_event, bad_event];

        let mut writer = Vec::new();
        let result = encoding.encode_input(events, &mut writer);
        assert!(result.is_err(), "batch with invalid GELF event must error");

        // All-or-nothing: nothing written to the writer since the internal buffer
        // never made it to write_all.
        assert_eq!(
            writer.len(),
            0,
            "writer must receive 0 bytes on serialization error (all-or-nothing)"
        );
    }

    #[test]
    fn test_batch_encoder_parquet_basic() {
        use vector_lib::codecs::encoding::{
            BatchSerializerConfig, ParquetSerializerConfig, ParquetSerializerOptions,
        };

        let schema = "message test { required binary name (UTF8); }";
        let cfg = BatchEncodingConfig {
            framing: None,
            encoding: BatchSerializerConfig::Parquet(ParquetSerializerConfig {
                parquet: ParquetSerializerOptions {
                    schema: schema.to_string(),
                    record_complete_event: None,
                    ignore_type_mismatch_for_optional: None,
                },
            }),
            transformer: Transformer::default(),
        };
        let encoding = {
            let (encoder, transformer) = cfg.build().expect("build");
            (transformer, encoder)
        };

        let events = vec![
            mk_log_event(&[("name", "alice")]),
            mk_log_event(&[("name", "bob")]),
        ];

        let mut writer = Vec::new();
        let (written, _) = encoding.encode_input(events, &mut writer).unwrap();

        assert!(written > 0, "Parquet output must be non-empty");
        assert_eq!(written, writer.len());
        // Parquet files start with magic bytes "PAR1"
        assert_eq!(
            &writer[..4],
            b"PAR1",
            "Parquet output must start with PAR1 magic bytes"
        );
    }

    #[test]
    fn test_batch_encoder_parquet_content_type() {
        use vector_lib::codecs::encoding::{
            BatchSerializerConfig, ParquetSerializerConfig, ParquetSerializerOptions,
        };

        let schema = "message test { required binary name (UTF8); }";
        let cfg = BatchEncodingConfig {
            framing: None,
            encoding: BatchSerializerConfig::Parquet(ParquetSerializerConfig {
                parquet: ParquetSerializerOptions {
                    schema: schema.to_string(),
                    record_complete_event: None,
                    ignore_type_mismatch_for_optional: None,
                },
            }),
            transformer: Transformer::default(),
        };
        let (encoder, _) = cfg.build().expect("build");

        assert_eq!(encoder.content_type(), "application/octet-stream");
    }
}
