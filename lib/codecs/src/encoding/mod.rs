//! A collection of support structures that are used in the process of encoding
//! events into bytes.

pub mod format;
pub mod framing;
pub mod batch;

pub use batch::EncapFramingConfig;
use itertools::{Itertools, Position};
use tokio_util::codec::Encoder;

use std::fmt::Debug;

use bytes::BytesMut;
pub use format::{
    AvroSerializer, AvroSerializerConfig, AvroSerializerOptions, CefSerializer,
    CefSerializerConfig, CsvSerializer, CsvSerializerConfig, GelfSerializer, GelfSerializerConfig,
    JsonSerializer, JsonSerializerConfig, JsonSerializerOptions, LogfmtSerializer,
    LogfmtSerializerConfig, NativeJsonSerializer, NativeJsonSerializerConfig, NativeSerializer,
    NativeSerializerConfig, ParquetSerializer, ParquetSerializerConfig, ParquetSerializerOptions,
    ProtobufSerializer, ProtobufSerializerConfig, ProtobufSerializerOptions, RawMessageSerializer,
    RawMessageSerializerConfig, TextSerializer, TextSerializerConfig,
};
pub use framing::{
    BoxedFramer, BoxedFramingError, BytesEncoder, BytesEncoderConfig, CharacterDelimitedEncoder,
    CharacterDelimitedEncoderConfig, CharacterDelimitedEncoderOptions, LengthDelimitedEncoder,
    LengthDelimitedEncoderConfig, NewlineDelimitedEncoder, NewlineDelimitedEncoderConfig,
};
use vector_config::configurable_component;
use vector_core::{config::DataType, event::Event, schema};

use crate::{actions::{Transformer, Encoder as EventEncoder}, encoding::batch::{EncapFramer, ConstFrameEncoder}};
pub use crate::encoding::{format::{SyslogSerializer, SyslogSerializerConfig, SyslogFormat, Rfc5424, SyslogTimeRes, Truncation}, framing::OctetCountedEncoder};

/// An error that occurred while building an encoder.
pub type BuildError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// An error that occurred while encoding structured events into byte frames.
#[derive(Debug)]
pub enum Error {
    /// The error occurred while encoding the byte frame boundaries.
    FramingError(BoxedFramingError),
    /// The error occurred while serializing a structured event into bytes.
    SerializingError(vector_common::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FramingError(error) => write!(formatter, "FramingError({})", error),
            Self::SerializingError(error) => write!(formatter, "SerializingError({})", error),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::FramingError(Box::new(error))
    }
}

/// Framing configuration.
#[configurable_component]
#[derive(Clone, Debug, Eq, PartialEq)]
#[serde(tag = "method", rename_all = "snake_case")]
#[configurable(metadata(docs::enum_tag_description = "The framing method."))]
pub enum FramingConfig {
    /// Event data is not delimited at all.
    Bytes,

    /// Event data is delimited by a single ASCII (7-bit) character.
    CharacterDelimited(CharacterDelimitedEncoderConfig),

    /// Event data is prefixed with its length in bytes.
    ///
    /// The prefix is a 32-bit unsigned integer, little endian.
    LengthDelimited(LengthDelimitedEncoderConfig),

    /// Event data is delimited by a newline (LF) character.
    NewlineDelimited,

    /// Octet counted framing as per RFC 5425.
    OctetCounted,
}

impl From<BytesEncoderConfig> for FramingConfig {
    fn from(_: BytesEncoderConfig) -> Self {
        Self::Bytes
    }
}

impl From<CharacterDelimitedEncoderConfig> for FramingConfig {
    fn from(config: CharacterDelimitedEncoderConfig) -> Self {
        Self::CharacterDelimited(config)
    }
}

impl From<LengthDelimitedEncoderConfig> for FramingConfig {
    fn from(config: LengthDelimitedEncoderConfig) -> Self {
        Self::LengthDelimited(config)
    }
}

impl From<NewlineDelimitedEncoderConfig> for FramingConfig {
    fn from(_: NewlineDelimitedEncoderConfig) -> Self {
        Self::NewlineDelimited
    }
}

impl FramingConfig {
    /// Build the `Framer` from this configuration.
    pub fn build(&self) -> Framer {
        match self {
            FramingConfig::Bytes => Framer::Bytes(BytesEncoderConfig.build()),
            FramingConfig::CharacterDelimited(config) => Framer::CharacterDelimited(config.build()),
            FramingConfig::LengthDelimited(config) => Framer::LengthDelimited(config.build()),
            FramingConfig::NewlineDelimited => {
                Framer::NewlineDelimited(NewlineDelimitedEncoderConfig.build())
            },
            FramingConfig::OctetCounted => Framer::OctetCounted(OctetCountedEncoder{}),
        }
    }
}

/// Produce a byte stream from byte frames.
#[derive(Debug, Clone)]
pub enum Framer {
    /// Uses a `BytesEncoder` for framing.
    Bytes(BytesEncoder),
    /// Uses a `CharacterDelimitedEncoder` for framing.
    CharacterDelimited(CharacterDelimitedEncoder),
    /// Uses a `LengthDelimitedEncoder` for framing.
    LengthDelimited(LengthDelimitedEncoder),
    /// Uses a `NewlineDelimitedEncoder` for framing.
    NewlineDelimited(NewlineDelimitedEncoder),
    /// Uses an opaque `Encoder` implementation for framing.
    Boxed(BoxedFramer),
    /// Uses a `OctetCounted` for framing.
    OctetCounted(OctetCountedEncoder),
}

impl From<BytesEncoder> for Framer {
    fn from(encoder: BytesEncoder) -> Self {
        Self::Bytes(encoder)
    }
}

impl From<CharacterDelimitedEncoder> for Framer {
    fn from(encoder: CharacterDelimitedEncoder) -> Self {
        Self::CharacterDelimited(encoder)
    }
}

impl From<LengthDelimitedEncoder> for Framer {
    fn from(encoder: LengthDelimitedEncoder) -> Self {
        Self::LengthDelimited(encoder)
    }
}

impl From<NewlineDelimitedEncoder> for Framer {
    fn from(encoder: NewlineDelimitedEncoder) -> Self {
        Self::NewlineDelimited(encoder)
    }
}

impl From<BoxedFramer> for Framer {
    fn from(encoder: BoxedFramer) -> Self {
        Self::Boxed(encoder)
    }
}

impl Encoder<()> for Framer {
    type Error = BoxedFramingError;

    fn encode(&mut self, _: (), buffer: &mut BytesMut) -> Result<(), Self::Error> {
        match self {
            Framer::Bytes(framer) => framer.encode((), buffer),
            Framer::CharacterDelimited(framer) => framer.encode((), buffer),
            Framer::LengthDelimited(framer) => framer.encode((), buffer),
            Framer::NewlineDelimited(framer) => framer.encode((), buffer),
            Framer::Boxed(framer) => framer.encode((), buffer),
            Framer::OctetCounted(framer) => framer.encode((), buffer),
        }
    }
}

/// Serializer configuration.
#[configurable_component]
#[derive(Clone, Debug, Eq, PartialEq)]
#[serde(tag = "codec", rename_all = "snake_case")]
#[configurable(metadata(docs::enum_tag_description = "The codec to use for encoding events."))]
pub enum SerializerConfig {
    /// Encodes an event as an [Apache Avro][apache_avro] message.
    ///
    /// [apache_avro]: https://avro.apache.org/
    Avro {
        /// Apache Avro-specific encoder options.
        avro: AvroSerializerOptions,
    },

    /// Encodes an event as a CEF (Common Event Format) formatted message.
    ///
    Cef(
        /// Options for the CEF encoder.
        CefSerializerConfig,
    ),

    /// Encodes an event as a CSV message.
    ///
    /// This codec must be configured with fields to encode.
    ///
    Csv(CsvSerializerConfig),

    /// Encodes an event as a [GELF][gelf] message.
    ///
    /// This codec is experimental for the following reason:
    ///
    /// The GELF specification is more strict than the actual Graylog receiver.
    /// Vector's encoder currently adheres more strictly to the GELF spec, with
    /// the exception that some characters such as `@`  are allowed in field names.
    ///
    /// Other GELF codecs such as Loki's, use a [Go SDK][implementation] that is maintained
    /// by Graylog, and is much more relaxed than the GELF spec.
    ///
    /// Going forward, Vector will use that [Go SDK][implementation] as the reference implementation, which means
    /// the codec may continue to relax the enforcement of specification.
    ///
    /// [gelf]: https://docs.graylog.org/docs/gelf
    /// [implementation]: https://github.com/Graylog2/go-gelf/blob/v2/gelf/reader.go
    Gelf,

    /// Encodes an event as [JSON][json].
    ///
    /// [json]: https://www.json.org/
    Json(JsonSerializerConfig),

    /// Encodes an event as a [logfmt][logfmt] message.
    ///
    /// [logfmt]: https://brandur.org/logfmt
    Logfmt,

    /// Encodes an event in the [native Protocol Buffers format][vector_native_protobuf].
    ///
    /// This codec is **[experimental][experimental]**.
    ///
    /// [vector_native_protobuf]: https://github.com/vectordotdev/vector/blob/master/lib/vector-core/proto/event.proto
    /// [experimental]: https://vector.dev/highlights/2022-03-31-native-event-codecs
    Native,

    /// Encodes an event in the [native JSON format][vector_native_json].
    ///
    /// This codec is **[experimental][experimental]**.
    ///
    /// [vector_native_json]: https://github.com/vectordotdev/vector/blob/master/lib/codecs/tests/data/native_encoding/schema.cue
    /// [experimental]: https://vector.dev/highlights/2022-03-31-native-event-codecs
    NativeJson,

    /// Encodes an event as a [Protobuf][protobuf] message.
    ///
    /// [protobuf]: https://protobuf.dev/
    Protobuf(ProtobufSerializerConfig),

    /// No encoding.
    ///
    /// This encoding uses the `message` field of a log event.
    ///
    /// Be careful if you are modifying your log events (for example, by using a `remap`
    /// transform) and removing the message field while doing additional parsing on it, as this
    /// could lead to the encoding emitting empty strings for the given event.
    RawMessage,

    /// Plain text encoding.
    ///
    /// This encoding uses the `message` field of a log event. For metrics, it uses an
    /// encoding that resembles the Prometheus export format.
    ///
    /// Be careful if you are modifying your log events (for example, by using a `remap`
    /// transform) and removing the message field while doing additional parsing on it, as this
    /// could lead to the encoding emitting empty strings for the given event.
    Text(TextSerializerConfig),

    /// Syslog encoding.
    Syslog(SyslogSerializerConfig),
}

impl From<AvroSerializerConfig> for SerializerConfig {
    fn from(config: AvroSerializerConfig) -> Self {
        Self::Avro { avro: config.avro }
    }
}

impl From<CefSerializerConfig> for SerializerConfig {
    fn from(config: CefSerializerConfig) -> Self {
        Self::Cef(config)
    }
}

impl From<CsvSerializerConfig> for SerializerConfig {
    fn from(config: CsvSerializerConfig) -> Self {
        Self::Csv(config)
    }
}

impl From<GelfSerializerConfig> for SerializerConfig {
    fn from(_: GelfSerializerConfig) -> Self {
        Self::Gelf
    }
}

impl From<JsonSerializerConfig> for SerializerConfig {
    fn from(config: JsonSerializerConfig) -> Self {
        Self::Json(config)
    }
}

impl From<LogfmtSerializerConfig> for SerializerConfig {
    fn from(_: LogfmtSerializerConfig) -> Self {
        Self::Logfmt
    }
}

impl From<NativeSerializerConfig> for SerializerConfig {
    fn from(_: NativeSerializerConfig) -> Self {
        Self::Native
    }
}

impl From<NativeJsonSerializerConfig> for SerializerConfig {
    fn from(_: NativeJsonSerializerConfig) -> Self {
        Self::NativeJson
    }
}

impl From<ProtobufSerializerConfig> for SerializerConfig {
    fn from(config: ProtobufSerializerConfig) -> Self {
        Self::Protobuf(config)
    }
}

impl From<RawMessageSerializerConfig> for SerializerConfig {
    fn from(_: RawMessageSerializerConfig) -> Self {
        Self::RawMessage
    }
}

impl From<TextSerializerConfig> for SerializerConfig {
    fn from(config: TextSerializerConfig) -> Self {
        Self::Text(config)
    }
}

impl SerializerConfig {
    /// Build the `Serializer` from this configuration.
    /// Fails if serializer is batched.
    pub fn build(&self) -> Result<Serializer, Box<dyn std::error::Error + Send + Sync + 'static>> {
        match self {
            SerializerConfig::Avro { avro } => Ok(Serializer::Avro(
                AvroSerializerConfig::new(avro.schema.clone()).build()?,
            )),
            SerializerConfig::Cef(config) => Ok(Serializer::Cef(config.build()?)),
            SerializerConfig::Csv(config) => Ok(Serializer::Csv(config.build()?)),
            SerializerConfig::Gelf => Ok(Serializer::Gelf(GelfSerializerConfig::new().build())),
            SerializerConfig::Json(config) => Ok(Serializer::Json(config.build())),
            SerializerConfig::Logfmt => Ok(Serializer::Logfmt(LogfmtSerializerConfig.build())),
            SerializerConfig::Native => Ok(Serializer::Native(NativeSerializerConfig.build())),
            SerializerConfig::NativeJson => {
                Ok(Serializer::NativeJson(NativeJsonSerializerConfig.build()))
            }
            SerializerConfig::Protobuf(config) => Ok(Serializer::Protobuf(config.build()?)),
            SerializerConfig::RawMessage => {
                Ok(Serializer::RawMessage(RawMessageSerializerConfig.build()))
            }
            SerializerConfig::Text(config) => Ok(Serializer::Text(config.build())),
            SerializerConfig::Syslog(config) => Ok(Serializer::Syslog(config.build()))
        }
    }

    /// Return an appropriate default framer for the given serializer.
    pub fn default_stream_framing(&self) -> FramingConfig {
        match self {
            // TODO: Technically, Avro messages are supposed to be framed[1] as a vector of
            // length-delimited buffers -- `len` as big-endian 32-bit unsigned integer, followed by
            // `len` bytes -- with a "zero-length buffer" to terminate the overall message... which
            // our length delimited framer obviously will not do.
            //
            // This is OK for now, because the Avro serializer is more ceremonial than anything
            // else, existing to curry serializer config options to Pulsar's native client, not to
            // actually serialize the bytes themselves... but we're still exposing this method and
            // we should do so accurately, even if practically it doesn't need to be.
            //
            // [1]: https://avro.apache.org/docs/1.11.1/specification/_print/#message-framing
            SerializerConfig::Avro { .. }
            | SerializerConfig::Native
            | SerializerConfig::Protobuf(_) => {
                FramingConfig::LengthDelimited(LengthDelimitedEncoderConfig::default())
            }
            SerializerConfig::Cef(_)
            | SerializerConfig::Csv(_)
            | SerializerConfig::Json(_)
            | SerializerConfig::Logfmt
            | SerializerConfig::NativeJson
            | SerializerConfig::RawMessage
            | SerializerConfig::Text(_) => FramingConfig::NewlineDelimited,
            SerializerConfig::Gelf => {
                FramingConfig::CharacterDelimited(CharacterDelimitedEncoderConfig::new(0))
            },
            // TODO(OBE-7927): is this the best default for syslog?
            SerializerConfig::Syslog(_) => FramingConfig::NewlineDelimited,
        }
    }

    /// The data type of events that are accepted by this `Serializer`.
    pub fn input_type(&self) -> DataType {
        match self {
            SerializerConfig::Avro { avro } => {
                AvroSerializerConfig::new(avro.schema.clone()).input_type()
            }
            SerializerConfig::Cef(config) => config.input_type(),
            SerializerConfig::Csv(config) => config.input_type(),
            SerializerConfig::Gelf { .. } => GelfSerializerConfig::input_type(),
            SerializerConfig::Json(config) => config.input_type(),
            SerializerConfig::Logfmt => LogfmtSerializerConfig.input_type(),
            SerializerConfig::Native => NativeSerializerConfig.input_type(),
            SerializerConfig::NativeJson => NativeJsonSerializerConfig.input_type(),
            SerializerConfig::Protobuf(config) => config.input_type(),
            SerializerConfig::RawMessage => RawMessageSerializerConfig.input_type(),
            SerializerConfig::Text(config) => config.input_type(),
            SerializerConfig::Syslog(config) => config.input_type(),
        }
    }

    /// The schema required by the serializer.
    pub fn schema_requirement(&self) -> schema::Requirement {
        match self {
            SerializerConfig::Avro { avro } => {
                AvroSerializerConfig::new(avro.schema.clone()).schema_requirement()
            }
            SerializerConfig::Cef(config) => config.schema_requirement(),
            SerializerConfig::Csv(config) => config.schema_requirement(),
            SerializerConfig::Gelf { .. } => GelfSerializerConfig::schema_requirement(),
            SerializerConfig::Json(config) => config.schema_requirement(),
            SerializerConfig::Logfmt => LogfmtSerializerConfig.schema_requirement(),
            SerializerConfig::Native => NativeSerializerConfig.schema_requirement(),
            SerializerConfig::NativeJson => NativeJsonSerializerConfig.schema_requirement(),
            SerializerConfig::Protobuf(config) => config.schema_requirement(),
            SerializerConfig::RawMessage => RawMessageSerializerConfig.schema_requirement(),
            SerializerConfig::Text(config) => config.schema_requirement(),
            SerializerConfig::Syslog(config) => config.schema_requirement(),
        }
    }
}

/// Serialize structured events as bytes.
#[derive(Debug, Clone)]
pub enum Serializer {
    /// Uses an `AvroSerializer` for serialization.
    Avro(AvroSerializer),
    /// Uses a `CefSerializer` for serialization.
    Cef(CefSerializer),
    /// Uses a `CsvSerializer` for serialization.
    Csv(CsvSerializer),
    /// Uses a `GelfSerializer` for serialization.
    Gelf(GelfSerializer),
    /// Uses a `JsonSerializer` for serialization.
    Json(JsonSerializer),
    /// Uses a `LogfmtSerializer` for serialization.
    Logfmt(LogfmtSerializer),
    /// Uses a `NativeSerializer` for serialization.
    Native(NativeSerializer),
    /// Uses a `NativeJsonSerializer` for serialization.
    NativeJson(NativeJsonSerializer),
    /// Uses a `ProtobufSerializer` for serialization.
    Protobuf(ProtobufSerializer),
    /// Uses a `RawMessageSerializer` for serialization.
    RawMessage(RawMessageSerializer),
    /// Uses a `TextSerializer` for serialization.
    Text(TextSerializer),
    /// Uses a `SyslogSerializer` for serialization.
    Syslog(SyslogSerializer),
}

impl Serializer {
    /// Check if the serializer supports encoding an event to JSON via `Serializer::to_json_value`.
    pub fn supports_json(&self) -> bool {
        match self {
            Serializer::Json(_) | Serializer::NativeJson(_) | Serializer::Gelf(_) => true,
            Serializer::Avro(_)
            | Serializer::Cef(_)
            | Serializer::Csv(_)
            | Serializer::Logfmt(_)
            | Serializer::Text(_)
            | Serializer::Native(_)
            | Serializer::Protobuf(_)
            | Serializer::RawMessage(_)
            | Serializer::Syslog(_) => false,
        }
    }

    /// Encode event and represent it as JSON value.
    ///
    /// # Panics
    ///
    /// Panics if the serializer does not support encoding to JSON. Call `Serializer::supports_json`
    /// if you need to determine the capability to encode to JSON at runtime.
    pub fn to_json_value(&self, event: Event) -> Result<serde_json::Value, vector_common::Error> {
        match self {
            Serializer::Gelf(serializer) => serializer.to_json_value(event),
            Serializer::Json(serializer) => serializer.to_json_value(event),
            Serializer::NativeJson(serializer) => serializer.to_json_value(event),
            Serializer::Avro(_)
            | Serializer::Cef(_)
            | Serializer::Csv(_)
            | Serializer::Logfmt(_)
            | Serializer::Text(_)
            | Serializer::Native(_)
            | Serializer::Protobuf(_)
            | Serializer::RawMessage(_)
            | Serializer::Syslog(_) => {
                panic!("Serializer does not support JSON")
            }
        }
    }
}

impl From<AvroSerializer> for Serializer {
    fn from(serializer: AvroSerializer) -> Self {
        Self::Avro(serializer)
    }
}

impl From<CefSerializer> for Serializer {
    fn from(serializer: CefSerializer) -> Self {
        Self::Cef(serializer)
    }
}

impl From<CsvSerializer> for Serializer {
    fn from(serializer: CsvSerializer) -> Self {
        Self::Csv(serializer)
    }
}

impl From<GelfSerializer> for Serializer {
    fn from(serializer: GelfSerializer) -> Self {
        Self::Gelf(serializer)
    }
}

impl From<JsonSerializer> for Serializer {
    fn from(serializer: JsonSerializer) -> Self {
        Self::Json(serializer)
    }
}

impl From<LogfmtSerializer> for Serializer {
    fn from(serializer: LogfmtSerializer) -> Self {
        Self::Logfmt(serializer)
    }
}

impl From<NativeSerializer> for Serializer {
    fn from(serializer: NativeSerializer) -> Self {
        Self::Native(serializer)
    }
}

impl From<NativeJsonSerializer> for Serializer {
    fn from(serializer: NativeJsonSerializer) -> Self {
        Self::NativeJson(serializer)
    }
}

impl From<ProtobufSerializer> for Serializer {
    fn from(serializer: ProtobufSerializer) -> Self {
        Self::Protobuf(serializer)
    }
}

impl From<RawMessageSerializer> for Serializer {
    fn from(serializer: RawMessageSerializer) -> Self {
        Self::RawMessage(serializer)
    }
}

impl From<TextSerializer> for Serializer {
    fn from(serializer: TextSerializer) -> Self {
        Self::Text(serializer)
    }
}

impl Encoder<Event> for Serializer {
    type Error = vector_common::Error;

    fn encode(&mut self, event: Event, buffer: &mut BytesMut) -> Result<(), Self::Error> {
        match self {
            Serializer::Avro(serializer) => serializer.encode(event, buffer),
            Serializer::Cef(serializer) => serializer.encode(event, buffer),
            Serializer::Csv(serializer) => serializer.encode(event, buffer),
            Serializer::Gelf(serializer) => serializer.encode(event, buffer),
            Serializer::Json(serializer) => serializer.encode(event, buffer),
            Serializer::Logfmt(serializer) => serializer.encode(event, buffer),
            Serializer::Native(serializer) => serializer.encode(event, buffer),
            Serializer::NativeJson(serializer) => serializer.encode(event, buffer),
            Serializer::Protobuf(serializer) => serializer.encode(event, buffer),
            Serializer::RawMessage(serializer) => serializer.encode(event, buffer),
            Serializer::Text(serializer) => serializer.encode(event, buffer),
            Serializer::Syslog(serializer) => serializer.encode(event, buffer),
        }
    }
}

/// Batch Framing configuration.
#[configurable_component]
#[derive(Clone, Debug, Eq, PartialEq, Default)]
#[serde(deny_unknown_fields)]
#[serde(tag = "method", rename_all = "snake_case")]
#[configurable(metadata(docs::enum_tag_description = "The framing method for encoded event-batches."))]
pub enum BatchFramerConfig {
    /// No framing; raw bytes.
    #[default]
    Identity,

    /// Encap
    Encap(EncapFramingConfig),
}

impl BatchFramerConfig {
    /// Build the `BatchFramer` from this configuration.
    pub fn build(&self) -> Result<BatchFramer, vector_common::Error> {
        match self {
            BatchFramerConfig::Identity => Ok(BatchFramer::Identity),
            BatchFramerConfig::Encap(config) => Ok(BatchFramer::Encap(config.build()?)),
        }
    }
}

/// Encoding configuration.
#[configurable_component]
#[derive(Clone, Debug, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EventEncodingConfig {
    /// Framing configuration.
    #[configurable(derived)]
    pub framing: Option<FramingConfig>,

    /// Encoding configuration
    #[configurable(derived)]
    pub serializer: SerializerConfig,
}

/// Batch Framing configuration.
#[configurable_component]
#[derive(Clone, Debug, Eq, PartialEq)]
#[serde(tag = "codec", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
#[configurable(metadata(docs::enum_tag_description = "Encoding to be used for event-batches."))]
pub enum BatchSerializerConfig {
    /// Stack per-event (non-batch) framing and serde
    Stack(EventEncodingConfig),

    /// Parquet
    Parquet(ParquetSerializerConfig),
}


impl BatchSerializerConfig {
    /// The data type of events that are accepted by this `BatchSerializer`.
    pub fn input_type(&self) -> DataType {
        match self {
            BatchSerializerConfig::Parquet(cfg) => ParquetSerializerConfig::new(
                cfg.parquet.schema.clone(),
                cfg.parquet.record_complete_event.clone(),
                cfg.parquet.ignore_type_mismatch_for_optional.clone(),
            )
            .input_type(),
            BatchSerializerConfig::Stack(cfg) => cfg.serializer.input_type(),
        }
    }

    /// Build the `BatchSerializer` from this configuration.
    /// Returns `None` if the serializer is not batched.
    pub fn build(
        &self,
    ) -> Result<BatchSerializer, vector_common::Error> {
        match self {
            BatchSerializerConfig::Parquet(cfg) => Ok(BatchSerializer::Parquet(
                ParquetSerializerConfig::new(
                    cfg.parquet.schema.clone(),
                    cfg.parquet.record_complete_event.clone(),
                    cfg.parquet.ignore_type_mismatch_for_optional.clone(),
                )
                .build()?,
            )),
            BatchSerializerConfig::Stack(cfg) => {
                let serializer = cfg.serializer.build()?;
                let framer = cfg.framing.as_ref().map(|c| c.clone()).unwrap_or(cfg.serializer.default_stream_framing()).build();
                Ok(BatchSerializer::Stack(StackSerializer(EventEncoder::<Framer>::new(framer, serializer))))
            },
        }
    }

}

/// Batch Encoding configuration.
#[configurable_component]
#[derive(Clone, Debug, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
#[configurable(description = "Configures how batches of events are encoded into raw bytes.")]
pub struct BatchEncodingConfig {
    /// Framing configuration for batches.
    ///
    /// When omitted (`None`), the framing is auto-detected from the inner
    /// serializer's `batch_prefix()` / `batch_suffix()`.  For example,
    /// comma-delimited JSON will automatically get `[` / `]` encapsulation.
    ///
    /// Set explicitly to `Identity` to opt out of auto-detection, or to
    /// `Encap(...)` to provide custom prefix/suffix bytes.
    #[serde(default)]
    pub framing: Option<BatchFramerConfig>,

    /// Serializer configuration for batches.
    pub encoding: BatchSerializerConfig,

    /// Transformation rules applied before encoding.
    #[serde(default)]
    pub transformer: Transformer,
}

/// Serialize collection of events as bytes using a stack of per-event `Serializer` and `Framer` for serialization.
#[derive(Debug, Clone)]
pub struct StackSerializer(EventEncoder<Framer>);

impl StackSerializer {
    /// Get the batch prefix from the inner encoder.
    pub fn batch_prefix(&self) -> &[u8] {
        self.0.batch_prefix()
    }

    /// Get the batch suffix from the inner encoder.
    pub fn batch_suffix(&self) -> &[u8] {
        self.0.batch_suffix()
    }
}

impl Encoder<Vec<Event>> for StackSerializer {
    type Error = vector_common::Error;

    fn encode(&mut self, events: Vec<Event>, buffer: &mut BytesMut) -> Result<(), Self::Error> {
        for (position, event) in events.into_iter().with_position() {
            match position {
                Position::Last | Position::Only => {
                    // Last (or only) event: serialize without trailing delimiter.
                    self.0.serialize(event, buffer)?;
                }
                _ => {
                    // All other events: serialize and append framing delimiter.
                    self.0.encode(event, buffer)?;
                }
            }
        }
        Ok(())
    }
}

/// Serialize collection of events as bytes.
#[derive(Debug, Clone)]
pub enum BatchSerializer {
    /// Uses a stack of per-event `Serializer` and `Framer` for serialization.
    Stack(StackSerializer),

    /// Uses a `ParquetSerializer` for serialization.
    Parquet(ParquetSerializer),
}

impl BatchSerializer {
    /// The content type produced by this serializer.
    pub fn content_type(&self) -> &'static str {
        match self {
            Self::Parquet(_) => "application/octet-stream",
            Self::Stack(ser) => ser.0.content_type(),
        }
    }

    /// Get the batch prefix from the inner serializer.
    pub fn batch_prefix(&self) -> &[u8] {
        match self {
            Self::Parquet(_) => &[],
            Self::Stack(ser) => ser.batch_prefix(),
        }
    }

    /// Get the batch suffix from the inner serializer.
    pub fn batch_suffix(&self) -> &[u8] {
        match self {
            Self::Parquet(_) => &[],
            Self::Stack(ser) => ser.batch_suffix(),
        }
    }
}

impl Encoder<Vec<Event>> for BatchSerializer {
    type Error = vector_common::Error;

    fn encode(&mut self, events: Vec<Event>, buffer: &mut BytesMut) -> Result<(), Self::Error> {
        match self {
            Self::Parquet(ser) => ser.encode(events, buffer),
            Self::Stack(ser) => ser.encode(events, buffer),
        }
    }
}

/// Batch framing configuration.
#[derive(Debug, Clone)]
pub enum BatchFramer {
    /// No framing; raw bytes.
    Identity,

    /// Framing with constant bytes at the start and end of batch-buffer
    Encap(EncapFramer),
}

impl BatchFramer {
    /// Encode framing into the buffer.
    pub fn encode(&mut self, buffer: &mut BytesMut) -> Result<(), BoxedFramingError> {
        match self {
            BatchFramer::Identity => Ok(()),
            BatchFramer::Encap(encap) => encap.encode((), buffer),
        }
    }
}

/// Encodes a batch of events using a `BatchSerializer` and `BatchFramer`.
#[derive(Debug, Clone)]
pub struct BatchEncoder {
    framer: BatchFramer,

    serializer: BatchSerializer,
}

impl BatchEncoder {
    /// The content type produced by this batch encoder.
    pub fn content_type(&self) -> &'static str {
        self.serializer.content_type()
    }
}

impl Encoder<Vec<Event>> for BatchEncoder {
    type Error = vector_common::Error;

    fn encode(&mut self, events: Vec<Event>, buffer: &mut BytesMut) -> Result<(), Self::Error> {
        self.serializer.encode(events, buffer)?;
        self.framer.encode(buffer)?;
        Ok(())
    }
}

impl BatchEncodingConfig {
    /// The data type of events that are accepted by this batch encoding config.
    pub fn input_type(&self) -> DataType {
        self.encoding.input_type()
    }

    /// The default file extension for this batch encoding config.
    pub fn file_extension(&self) -> Option<&'static str> {
        match &self.encoding {
            BatchSerializerConfig::Parquet(_) => Some("parquet"),
            BatchSerializerConfig::Stack(_) => None,
        }
    }

    /// Build the `BatchEncoder` and `Transformer` from this configuration.
    ///
    /// When `framing` is `None`, auto-detection kicks in: the serializer is
    /// built first, and its `batch_prefix()` / `batch_suffix()` are probed.
    /// If both are non-empty an `Encap` framer is constructed automatically;
    /// otherwise the framer defaults to `Identity` (no wrapping).
    pub fn build(&self) -> Result<(BatchEncoder, Transformer), vector_common::Error> {
        let serializer = self.encoding.build()?;

        let framer = match &self.framing {
            Some(BatchFramerConfig::Identity) => BatchFramer::Identity,
            Some(BatchFramerConfig::Encap(config)) => BatchFramer::Encap(config.build()?),
            None => {
                // Auto-detect from the serializer's batch_prefix / batch_suffix.
                let prefix = serializer.batch_prefix();
                let suffix = serializer.batch_suffix();
                if prefix.is_empty() && suffix.is_empty() {
                    BatchFramer::Identity
                } else {
                    BatchFramer::Encap(EncapFramer::Const(
                        ConstFrameEncoder::new(prefix.to_vec(), suffix.to_vec()),
                    ))
                }
            }
        };

        Ok((BatchEncoder { framer, serializer }, self.transformer.clone()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use assert_matches::assert_matches;

    use crate::actions::{Transformer, TimestampFormat};
    use crate::encoding::{BatchEncoder, BatchEncodingConfig, BatchFramer, BatchFramerConfig, BatchSerializer, BatchSerializerConfig, CharacterDelimitedEncoder, CharacterDelimitedEncoderConfig, EventEncodingConfig, FramingConfig, JsonSerializerConfig, NewlineDelimitedEncoder, ParquetSerializerConfig, ParquetSerializerOptions, Serializer, SerializerConfig, StackSerializer};
    use bytes::BytesMut;
    use tokio_util::codec::Encoder;
    use vector_core::event::{Event, LogEvent, Value};
    use vrl::value::KeyString;

    #[test]
    fn batch_encoding_config_parquet() {
        let c = r#"
            encoding.codec = "parquet"
            [encoding.parquet]
            schema = "message test { required group data { required binary name; repeated int64 values; } }"
            record_complete_event = true
            ignore_type_mismatch_for_optional = true

            [transformer]
            except_fields = ["drop_me"]
            timestamp_format = "unix"
        "#;

        let cfg: BatchEncodingConfig = toml::from_str(c).expect("deser");

        assert_matches!(cfg.framing, None);
        assert_matches!(
            cfg.encoding,
            BatchSerializerConfig::Parquet(ParquetSerializerConfig {
                parquet: ParquetSerializerOptions {
                    schema,
                    ignore_type_mismatch_for_optional: Some(true),
                    record_complete_event: Some(true),
                },
            }) if schema.as_str() == "message test { required group data { required binary name; repeated int64 values; } }"
        );

        assert_eq!(cfg.transformer.except_fields(), &Some(vec!["drop_me".into()]));
        assert_eq!(cfg.transformer.timestamp_format(), &Some(TimestampFormat::Unix));
    }

    #[test]
    fn batch_encoding_config_parquet_no_transformer() {
        let c = r#"
            encoding.codec = "parquet"
            [encoding.parquet]
            schema = "message test { required group data { required binary name; } }"
        "#;

        let cfg: BatchEncodingConfig = toml::from_str(c).expect("deser");

        assert_matches!(cfg.framing, None);
        assert_matches!(cfg.encoding, BatchSerializerConfig::Parquet(_));
        assert_eq!(cfg.transformer, Transformer::default());
    }

    #[test]
    fn batch_encoding_config_legacy_no_transformer_with_framing() {
        let c = r#"
            [encoding]
            codec = "stack"
            [encoding.serializer]
            codec = "json"
            [encoding.framing]
            method = "octet_counted"

            [transformer]
            except_fields = ["drop_me"]
            timestamp_format = "unix"
        "#;

        let cfg: BatchEncodingConfig = toml::from_str(c).expect("deser");

        assert_matches!(cfg.framing, None);

        let expected_transformer = Transformer::new(None, Some(vec!["drop_me".into()]), Some(TimestampFormat::Unix), BTreeMap::new()).unwrap();

        assert_matches!(
            cfg.build(),
            Ok((
                    BatchEncoder{
                        framer: BatchFramer::Identity,
                        serializer: BatchSerializer::Stack(StackSerializer(EventEncoder::<super::Framer>{
                            framer: super::Framer::OctetCounted(_),
                            serializer: Serializer::Json(_),
                        })),
                    },
                    t)) if t == expected_transformer);
    }

    use crate::actions::Encoder as EventEncoder;

    #[test]
    fn batch_encoding_config_legacy_no_transformer() {
        let c = r#"
            [encoding]
            codec = "stack"
            [encoding.serializer]
            codec = "json"
        "#;

        let cfg: BatchEncodingConfig = toml::from_str(c).expect("deser");

        assert_matches!(
            cfg.build(),
            Ok((
                    BatchEncoder{
                        framer: BatchFramer::Identity,
                        serializer: BatchSerializer::Stack(StackSerializer(EventEncoder::<super::Framer>{
                            framer: super::Framer::NewlineDelimited(_),
                            serializer: Serializer::Json(_),
                        })),
                    },
                    t)) if t == Transformer::default());

        assert_matches!(cfg.framing, None);
    }

    fn test_encap_framing(prefix_hex: Option<&str>, suffix_hex: Option<&str>, expected_prefix: &str, expected_suffix: &str) {
        let framing_lines = match (prefix_hex, suffix_hex) {
            (Some(p), Some(s)) => format!("prefix = \"{p}\"\nsuffix = \"{s}\""),
            (Some(p), None) => format!("prefix = \"{p}\""),
            (None, Some(s)) => format!("suffix = \"{s}\""),
            (None, None) => String::new(),
        };

        let c = format!(r#"
            [framing]
            method = "encap"
            [framing.const]
            {framing_lines}

            [encoding]
            codec = "stack"
            [encoding.serializer]
            codec = "csv"
            [encoding.serializer.csv]
            fields = ["name", "val"]
            delimiter = ";"
            quote_style = "always"

            [transformer]
            except_fields = ["ignore"]
        "#);

        let cfg: BatchEncodingConfig = toml::from_str(&c).expect("deser");
        assert_matches!(cfg.framing, Some(BatchFramerConfig::Encap(_)));
        assert_matches!(cfg.encoding, BatchSerializerConfig::Stack(_));
        assert_eq!(cfg.transformer.except_fields(), &Some(vec!["ignore".into()]));

        let (mut enc, transformer) = cfg.build().expect("build");
        assert_eq!(transformer.except_fields(), &Some(vec!["ignore".into()]));

        let mk = |pairs: &[(&str, &str)]| -> Event {
            let mut e = LogEvent::default();
            for (k, v) in pairs {
                e.insert(*k, Value::from(*v));
            }
            e.into()
        };
        let events: Vec<Event> = vec![
            mk(&[("name", "alice"), ("val", "100")]),
            mk(&[("name", "bob"), ("val", "200")]),
        ];

        let mut buf = BytesMut::new();
        enc.encode(events, &mut buf).expect("encode");
        let out = String::from_utf8(buf.to_vec()).expect("utf8");

        assert!(out.starts_with(expected_prefix), "expected prefix {expected_prefix:?}, got: {out:?}");
        assert!(out.ends_with(expected_suffix), "expected suffix {expected_suffix:?}, got: {out:?}");

        let inner = &out[expected_prefix.len()..out.len() - expected_suffix.len()];
        assert!(inner.contains(";"), "expected ; delimiter, got: {inner}");
        assert!(inner.contains("\"alice\""), "expected quoted alice, got: {inner}");
        assert!(inner.contains("\"bob\""), "expected quoted bob, got: {inner}");
    }

    #[test]
    fn batch_encoding_stacked_csv_with_encap_framing() {
        test_encap_framing(Some("5b5b"), Some("5d5d"), "[[", "]]");
    }

    #[test]
    fn batch_encoding_stacked_csv_with_encap_prefix_only() {
        test_encap_framing(Some("0A0A"), None, "\n\n", "");
    }

    #[test]
    fn batch_encoding_stacked_csv_with_encap_suffix_only() {
        test_encap_framing(None, Some("0A0A"), "", "\n\n");
    }

    fn mk_event(pairs: &[(&str, &str)]) -> Event {
        LogEvent::from(
            pairs
                .iter()
                .map(|(k, v)| (KeyString::from(*k), Value::from(*v)))
                .collect::<std::collections::BTreeMap<_, _>>(),
        )
        .into()
    }

    fn build_stack_serializer(framer: super::Framer, serializer: Serializer) -> StackSerializer {
        StackSerializer(EventEncoder::<super::Framer>::new(framer, serializer))
    }

    #[test]
    fn test_stack_serializer_ndjson_no_trailing_newline() {
        let mut ser = build_stack_serializer(
            NewlineDelimitedEncoder::default().into(),
            JsonSerializerConfig::default().build().into(),
        );

        let events = vec![
            mk_event(&[("key", "value1")]),
            mk_event(&[("key", "value2")]),
            mk_event(&[("key", "value3")]),
        ];

        let mut buf = BytesMut::new();
        ser.encode(events, &mut buf).expect("encode");
        let out = String::from_utf8(buf.to_vec()).expect("utf8");

        assert_eq!(
            out,
            "{\"key\":\"value1\"}\n{\"key\":\"value2\"}\n{\"key\":\"value3\"}"
        );
        assert!(!out.ends_with('\n'), "must not have trailing newline");
    }

    #[test]
    fn test_stack_serializer_comma_json_no_trailing_comma() {
        let mut ser = build_stack_serializer(
            CharacterDelimitedEncoder::new(b',').into(),
            JsonSerializerConfig::default().build().into(),
        );

        let events = vec![
            mk_event(&[("key", "value1")]),
            mk_event(&[("key", "value2")]),
            mk_event(&[("key", "value3")]),
        ];

        let mut buf = BytesMut::new();
        ser.encode(events, &mut buf).expect("encode");
        let out = String::from_utf8(buf.to_vec()).expect("utf8");

        assert_eq!(
            out,
            "{\"key\":\"value1\"},{\"key\":\"value2\"},{\"key\":\"value3\"}"
        );
        assert!(!out.ends_with(','), "must not have trailing comma");
    }

    #[test]
    fn test_stack_serializer_single_event_no_delimiter() {
        let mut ser = build_stack_serializer(
            NewlineDelimitedEncoder::default().into(),
            JsonSerializerConfig::default().build().into(),
        );

        let events = vec![mk_event(&[("key", "value")])];

        let mut buf = BytesMut::new();
        ser.encode(events, &mut buf).expect("encode");
        let out = String::from_utf8(buf.to_vec()).expect("utf8");

        assert_eq!(out, "{\"key\":\"value\"}");
        assert!(!out.ends_with('\n'), "single event must not have trailing newline");
    }

    #[test]
    fn test_stack_serializer_empty_events() {
        let mut ser = build_stack_serializer(
            NewlineDelimitedEncoder::default().into(),
            JsonSerializerConfig::default().build().into(),
        );

        let events: Vec<Event> = vec![];

        let mut buf = BytesMut::new();
        ser.encode(events, &mut buf).expect("encode");
        assert_eq!(buf.len(), 0, "empty input must produce empty output");
    }

    // ---- Gap 2: Auto-detect batch prefix/suffix tests ----

    #[test]
    fn test_batch_encoder_auto_encap_for_comma_delimited_json() {
        // Comma-delimited JSON with no explicit batch framing → should auto-produce [/] wrapping.
        let cfg = BatchEncodingConfig {
            framing: None,
            encoding: BatchSerializerConfig::Stack(EventEncodingConfig {
                framing: Some(FramingConfig::CharacterDelimited(
                    CharacterDelimitedEncoderConfig::new(b','),
                )),
                serializer: SerializerConfig::Json(JsonSerializerConfig::default()),
            }),
            transformer: Transformer::default(),
        };

        let (mut enc, _) = cfg.build().expect("build");

        let events = vec![
            mk_event(&[("a", "1")]),
            mk_event(&[("a", "2")]),
        ];
        let mut buf = BytesMut::new();
        enc.encode(events, &mut buf).expect("encode");
        let out = String::from_utf8(buf.to_vec()).expect("utf8");

        assert!(out.starts_with('['), "expected [ prefix, got: {out}");
        assert!(out.ends_with(']'), "expected ] suffix, got: {out}");
        // Inner content should be comma-separated JSON without trailing comma.
        let inner = &out[1..out.len() - 1];
        assert!(inner.contains(','), "expected comma delimiter, got: {inner}");
        assert!(!inner.ends_with(','), "must not have trailing comma in: {inner}");
    }

    #[test]
    fn test_batch_encoder_explicit_identity_overrides_auto_encap() {
        // Same codec as above but with explicit Identity batch framing → no wrapping.
        let cfg = BatchEncodingConfig {
            framing: Some(BatchFramerConfig::Identity),
            encoding: BatchSerializerConfig::Stack(EventEncodingConfig {
                framing: Some(FramingConfig::CharacterDelimited(
                    CharacterDelimitedEncoderConfig::new(b','),
                )),
                serializer: SerializerConfig::Json(JsonSerializerConfig::default()),
            }),
            transformer: Transformer::default(),
        };

        let (mut enc, _) = cfg.build().expect("build");

        let events = vec![
            mk_event(&[("a", "1")]),
            mk_event(&[("a", "2")]),
        ];
        let mut buf = BytesMut::new();
        enc.encode(events, &mut buf).expect("encode");
        let out = String::from_utf8(buf.to_vec()).expect("utf8");

        assert!(!out.starts_with('['), "should NOT have [ prefix when Identity is explicit, got: {out}");
        assert!(!out.ends_with(']'), "should NOT have ] suffix when Identity is explicit, got: {out}");
    }

    #[test]
    fn test_batch_encoder_auto_identity_for_ndjson() {
        // Newline-delimited JSON with no explicit batch framing → Identity (no wrapping).
        let cfg = BatchEncodingConfig {
            framing: None,
            encoding: BatchSerializerConfig::Stack(EventEncodingConfig {
                framing: Some(FramingConfig::NewlineDelimited),
                serializer: SerializerConfig::Json(JsonSerializerConfig::default()),
            }),
            transformer: Transformer::default(),
        };

        let (mut enc, _) = cfg.build().expect("build");

        let events = vec![
            mk_event(&[("a", "1")]),
            mk_event(&[("a", "2")]),
        ];
        let mut buf = BytesMut::new();
        enc.encode(events, &mut buf).expect("encode");
        let out = String::from_utf8(buf.to_vec()).expect("utf8");

        assert!(!out.starts_with('['), "ndjson should NOT have [ prefix, got: {out}");
        assert!(!out.ends_with(']'), "ndjson should NOT have ] suffix, got: {out}");
        assert!(out.contains('\n'), "ndjson should have newline delimiters, got: {out}");
    }

    #[test]
    fn test_batch_encoder_auto_encap_for_native_json_comma() {
        // Comma-delimited NativeJson with no explicit batch framing → should auto-produce [/] wrapping.
        let cfg = BatchEncodingConfig {
            framing: None,
            encoding: BatchSerializerConfig::Stack(EventEncodingConfig {
                framing: Some(FramingConfig::CharacterDelimited(
                    CharacterDelimitedEncoderConfig::new(b','),
                )),
                serializer: SerializerConfig::NativeJson,
            }),
            transformer: Transformer::default(),
        };

        let (mut enc, _) = cfg.build().expect("build");

        let events = vec![
            mk_event(&[("a", "1")]),
            mk_event(&[("a", "2")]),
        ];
        let mut buf = BytesMut::new();
        enc.encode(events, &mut buf).expect("encode");
        let out = String::from_utf8(buf.to_vec()).expect("utf8");

        assert!(out.starts_with('['), "expected [ prefix for native_json + comma, got: {out}");
        assert!(out.ends_with(']'), "expected ] suffix for native_json + comma, got: {out}");
    }

    // ---- Gap 5: Empty events handling tests ----

    #[test]
    fn test_batch_encoder_empty_events_identity_framer() {
        // Empty events with Identity framer (ndjson) → 0 bytes.
        let cfg = BatchEncodingConfig {
            framing: None,
            encoding: BatchSerializerConfig::Stack(EventEncodingConfig {
                framing: Some(FramingConfig::NewlineDelimited),
                serializer: SerializerConfig::Json(JsonSerializerConfig::default()),
            }),
            transformer: Transformer::default(),
        };

        let (mut enc, _) = cfg.build().expect("build");

        let events: Vec<Event> = vec![];
        let mut buf = BytesMut::new();
        enc.encode(events, &mut buf).expect("encode");
        assert_eq!(buf.len(), 0, "empty events with ndjson (identity framer) must produce 0 bytes");
    }

    #[test]
    fn test_batch_encoder_empty_events_auto_encap_framer() {
        // Empty events with auto-detected Encap framer (comma-delimited JSON) → `[]`.
        let cfg = BatchEncodingConfig {
            framing: None,
            encoding: BatchSerializerConfig::Stack(EventEncodingConfig {
                framing: Some(FramingConfig::CharacterDelimited(
                    CharacterDelimitedEncoderConfig::new(b','),
                )),
                serializer: SerializerConfig::Json(JsonSerializerConfig::default()),
            }),
            transformer: Transformer::default(),
        };

        let (mut enc, _) = cfg.build().expect("build");

        let events: Vec<Event> = vec![];
        let mut buf = BytesMut::new();
        enc.encode(events, &mut buf).expect("encode");
        let out = String::from_utf8(buf.to_vec()).expect("utf8");
        assert_eq!(out, "[]", "empty events with comma-delimited JSON must produce []");
    }
}
