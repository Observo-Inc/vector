use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use codecs::BytesDeserializerConfig;
use lookup::lookup_v2::parse_value_path;
use lookup::{event_path, owned_value_path, path};
use smallvec::{smallvec, SmallVec};
use vector_config::configurable_component;
use vector_core::{
    config::{LegacyKey, LogNamespace},
    schema::Definition,
};
use vrl::value::kind::Collection;
use vrl::value::Kind;

use super::super::util::net::{SocketListenAddr, TcpSource, TcpSourceAck, TcpSourceAcker};
use crate::sources::splunk_s2s::s2s_decoder::{S2SDecoder, S2SDecoderError, S2SEventFrame};
use crate::{
    config::{
        log_schema, DataType, GenerateConfig, Resource, SourceAcknowledgementsConfig, SourceConfig,
        SourceContext, SourceOutput,
    },
    event::{Event, Value},
    serde::bool_or_struct,
    tcp::TcpKeepaliveConfig,
    tls::{MaybeTlsSettings, TlsSourceConfig},
    types,
};
use vector_core::source::Source;

/// Configuration for the `SplunkS2S` source.
#[configurable_component(source("splunk_s2s", "Collect logs from a SplunkUF agent."))]
#[derive(Clone, Debug)]
pub struct SplunkS2SConfig {
    #[configurable(derived)]
    address: SocketListenAddr,

    #[configurable(derived)]
    #[configurable(metadata(docs::advanced))]
    keepalive: Option<TcpKeepaliveConfig>,

    #[configurable(derived)]
    tls: Option<TlsSourceConfig>,

    /// The size of the receive buffer used for each connection.
    #[configurable(metadata(docs::type_unit = "bytes"))]
    #[configurable(metadata(docs::examples = 65536))]
    #[configurable(metadata(docs::advanced))]
    receive_buffer_bytes: Option<usize>,

    /// The maximum number of TCP connections that are allowed at any given time.
    #[configurable(metadata(docs::type_unit = "connections"))]
    #[configurable(metadata(docs::advanced))]
    connection_limit: Option<u32>,

    #[configurable(derived)]
    #[serde(default, deserialize_with = "bool_or_struct")]
    acknowledgements: SourceAcknowledgementsConfig,

    /// The namespace to use for logs. This overrides the global setting.
    #[configurable(metadata(docs::hidden))]
    #[serde(default)]
    log_namespace: Option<bool>,
}

impl SplunkS2SConfig {
    /// Builds the `schema::Definition` for this source using the provided `LogNamespace`.
    fn schema_definition(&self, log_namespace: LogNamespace) -> Definition {
        // `host_key` is only inserted if not present already.
        let host_key = parse_value_path(log_schema().host_key())
            .ok()
            .map(LegacyKey::InsertIfEmpty);

        let tls_client_metadata_path = self
            .tls
            .as_ref()
            .and_then(|tls| tls.client_metadata_key.as_ref())
            .and_then(|k| k.path.clone())
            .map(LegacyKey::Overwrite);

        BytesDeserializerConfig
            .schema_definition(log_namespace)
            .with_standard_vector_source_metadata()
            .with_source_metadata(
                SplunkS2SConfig::NAME,
                None,
                &owned_value_path!("timestamp"),
                Kind::timestamp().or_undefined(),
                Some("timestamp"),
            )
            .with_source_metadata(
                SplunkS2SConfig::NAME,
                host_key,
                &owned_value_path!("host"),
                Kind::bytes(),
                Some("host"),
            )
            .with_source_metadata(
                Self::NAME,
                tls_client_metadata_path,
                &owned_value_path!("tls_client_metadata"),
                Kind::object(Collection::empty().with_unknown(Kind::bytes())).or_undefined(),
                None,
            )
    }
}

impl Default for SplunkS2SConfig {
    fn default() -> Self {
        Self {
            address: SocketListenAddr::SocketAddr("0.0.0.0:9997".parse().unwrap()),
            keepalive: None,
            tls: None,
            receive_buffer_bytes: None,
            acknowledgements: Default::default(),
            connection_limit: None,
            log_namespace: None,
        }
    }
}

impl GenerateConfig for SplunkS2SConfig {
    fn generate_config() -> toml::Value {
        toml::Value::try_from(SplunkS2SConfig::default()).unwrap()
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "splunk_s2s")]
impl SourceConfig for SplunkS2SConfig {
    async fn build(&self, cx: SourceContext) -> crate::Result<Source> {
        let log_namespace = cx.log_namespace(self.log_namespace);
        let source = SplunkS2SSource {
            timestamp_converter: types::Conversion::Timestamp(cx.globals.timezone()),
            log_namespace,
        };
        let shutdown_secs = Duration::from_secs(30);
        let tls_config = self.tls.as_ref().map(|tls| tls.tls_config.clone());
        let tls_client_metadata_key = self
            .tls
            .as_ref()
            .and_then(|tls| tls.client_metadata_key.clone())
            .and_then(|k| k.path);

        let tls = MaybeTlsSettings::from_config(&tls_config, true)?;
        source.run(
            self.address,
            self.keepalive,
            shutdown_secs,
            tls,
            tls_client_metadata_key,
            self.receive_buffer_bytes,
            None,
            cx,
            self.acknowledgements,
            self.connection_limit,
            SplunkS2SConfig::NAME,
            log_namespace,
        )
    }

    fn outputs(&self, global_log_namespace: LogNamespace) -> Vec<SourceOutput> {
        // There is a global and per-source `log_namespace` config.
        // The source config overrides the global setting and is merged here.
        vec![SourceOutput::new_logs(
            DataType::Log,
            self.schema_definition(global_log_namespace.merge(self.log_namespace)),
        )]
    }

    fn resources(&self) -> Vec<Resource> {
        vec![self.address.as_tcp_resource()]
    }

    fn can_acknowledge(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone)]
struct SplunkS2SSource {
    timestamp_converter: types::Conversion,
    log_namespace: LogNamespace,
}

impl TcpSource for SplunkS2SSource {
    type Error = S2SDecoderError;
    type Item = S2SEventFrame;
    type Decoder = S2SDecoder;
    type Acker = SplunkS2SAcker;

    fn decoder(&self) -> Self::Decoder {
        S2SDecoder::new()
    }

    fn handle_events(&self, events: &mut [Event], _host: SocketAddr) {
        let _now = chrono::Utc::now();
        for event in events {
            let log = event.as_mut_log();

            self.log_namespace.insert_vector_metadata(
                log,
                Some(log_schema().source_type_key()),
                path!("source_type"),
                Bytes::from_static(SplunkS2SConfig::NAME.as_bytes()),
            );

            let _log_timestamp = log.get(event_path!("@timestamp")).and_then(|timestamp| {
                self.timestamp_converter
                    .convert::<Value>(timestamp.coerce_to_bytes())
                    .ok()
            });

        }
    }

    fn build_acker(&self, frames: &[Self::Item]) -> Self::Acker {
        SplunkS2SAcker::new(frames)
    }
}

struct SplunkS2SAcker {
    handshake_buffer: Option<Vec<u8>>,
}

impl SplunkS2SAcker {
    fn new(frames: &[S2SEventFrame]) -> Self {
        let mut handshake_buffer: Option<Vec<u8>> = None;
        for s2s_frame in frames {
            if s2s_frame.header_buffer.is_some() {
                handshake_buffer = s2s_frame.header_buffer.clone();
                break;
            }
        }
        Self {
            handshake_buffer,
        }
    }
}

impl TcpSourceAcker for SplunkS2SAcker {
    fn build_ack(self, _ack: TcpSourceAck) -> Option<Bytes> {
        if self.handshake_buffer.is_some() {
            return Some(Bytes::from(self.handshake_buffer.unwrap()))
        }
        None
    }
}

/// Normalized event from SplunkS2S frame
#[derive(Debug)]
struct SplunkS2SEventFrame {
    _sequence_number: u32,
    _fields: BTreeMap<String, serde_json::Value>,
}

impl From<S2SEventFrame> for Event {
    fn from(frame: S2SEventFrame) -> Self {
        Event::Log(frame.get_log_event())
    }
}

impl From<S2SEventFrame> for SmallVec<[Event; 1]> {
    fn from(frame: S2SEventFrame) -> Self {
        smallvec![frame.into()]
    }
}