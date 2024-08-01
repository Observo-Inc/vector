use crate::decoding::BoxedFramingError;
use bytes::{Buf, Bytes};
use bytes::{BytesMut};
use netflow_parser::variable_versions::common::FieldValue;
use netflow_parser::{NetflowPacketResult, NetflowParser};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex};
use tokio_util::codec::{Decoder, LinesCodecError};
use tracing::warn;
use vector_config::configurable_component;
use vrl::core::Value;
use byteorder::{ByteOrder, NetworkEndian};


/// Config used to build a `NetflowDecoderDecoder`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetflowDecoderConfig {
    /// Options for the netflow decoder.
    pub netflow_decoder_options: NetflowDecoderOptions,
}

impl NetflowDecoderConfig {
    /// Build the `NetflowDecoderDecoder` from this configuration.
    pub fn build(&self) -> NetflowDecoder {
        if let Some(max_length) = self.netflow_decoder_options.max_length {
            NetflowDecoder::new_with_max_length(max_length)
        } else {
            NetflowDecoder::new()
        }
    }
}

/// Options for building a `NetflowDecoderDecoder`.
#[configurable_component]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetflowDecoderOptions {
    /// The maximum length of the byte buffer.
    ///
    /// This length does *not* include the trailing delimiter.
    ///
    /// By default, there is no maximum length enforced. If events are malformed, this can lead to
    /// additional resource usage as events continue to be buffered in memory, and can potentially
    /// lead to memory exhaustion in extreme cases.
    ///
    /// If there is a risk of processing malformed data, such as logs with user-controlled input,
    /// consider setting the maximum length to a reasonably large value as a safety net. This
    /// ensures that processing is not actually unbounded.
    #[serde(skip_serializing_if = "vector_core::serde::skip_serializing_if_default")]
    pub max_length: Option<usize>,
}

impl NetflowDecoderOptions {
    /// Create a `NetflowDecoderDecoderOptions` with a delimiter and optional max_length.
    pub fn new(max_length: Option<usize>) -> Self {
        Self { max_length }
    }
}

/// A decoder for handling netflow packets. Will be moved to its own source in future.
#[derive(Clone, Debug)]
pub struct NetflowDecoder {
    /// The maximum length of the byte buffer.
    pub max_length: usize,
    parser: Arc<Mutex<NetflowParser>>,
}

impl NetflowDecoder {
    /// Creates a `NetflowDecoderDecoder` with a default maximum frame length limit.
    ///
    /// Any frames longer than `max_length` bytes will be discarded entirely.
    pub fn new() -> Self {
        // Use a more reasonable default maximum length
        Self::new_with_max_length(65536) // 64KB is a common maximum for UDP packets
    }

    /// Creates a `NetflowDecoderDecoder` with a maximum frame length limit.
    ///
    /// Any frames longer than `max_length` bytes will be discarded entirely.
    pub fn new_with_max_length(max_length: usize) -> Self {
        Self {
            max_length,
            parser: Arc::new(Mutex::new(NetflowParser::default())), // Initialize with Arc
            //buffer: Default::default(),
        }
    }

    /// Returns the maximum frame length when decoding.
    pub const fn max_length(&self) -> usize {
        self.max_length
    }
}

pub const NETFLOW_V9_VERSION: u16 = 9;
impl Decoder for NetflowDecoder {
    type Item = Bytes; // Output is json as bytes
    type Error = BoxedFramingError; // Or a custom error type

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        //We can do elaborate error handling here but it will not help much as the underlying protocol is broken
        if src.len() < 20 {
            return Ok(None)
        }

        let version: u16 = NetworkEndian::read_u16(&src[0..2]);

        if version != NETFLOW_V9_VERSION {
            src.clear();
            warn!(
                message = "Non v9 packet found",
                internal_log_rate_limit = true
            );
            return Err(BoxedFramingError::from(LinesCodecError::Io(
                io::Error::new(io::ErrorKind::Other, "Non v9 packet discarding buf"),
            )));
        }

        if src.len() > self.max_length {
            warn!(
                message = "Discarding frame larger than max_length.",
                buf_len = src.len(),
                max_length = self.max_length,
                internal_log_rate_limit = true
            );
            src.clear();
            return Err(BoxedFramingError::from(LinesCodecError::Io(
                io::Error::new(io::ErrorKind::Other, "Frame length limit exceeded"),
            )));
        }

        let mut packets = Vec::new();
        let mut parser = self.parser.lock().expect("Failed to lock NetflowParser");
        let parse_results = parser.parse_bytes(src.as_mut());

        let mut all_done = true;
        for result in parse_results {
            match result {
                NetflowPacketResult::Error(err) => {
                    warn!(
                        message = "Error parsing NetFlow packet",
                        internal_log_rate_limit = true
                    );
                    src.advance(src.len() - err.remaining.len());
                    //Can be possible corrupt message which we handle in next decode call
                    all_done = false
                }
                NetflowPacketResult::V9(v9pkt) => {
                    for flowset in v9pkt.flowsets {
                        if let Some(data) = flowset.body.data {
                            if flowset.header.flow_set_id > 255 {
                                for pkts in data.data_fields {
                                    let mut pkt: BTreeMap<String, Value> = BTreeMap::new();
                                    pkt.insert(
                                        "version".parse().unwrap(),
                                        Value::from(v9pkt.header.version),
                                    );
                                    pkt.insert(
                                        "sys_up_time".parse().unwrap(),
                                        Value::from(v9pkt.header.sys_up_time),
                                    );
                                    pkt.insert(
                                        "unix_secs".parse().unwrap(),
                                        Value::from(v9pkt.header.unix_secs),
                                    );
                                    pkt.insert(
                                        "source_id".parse().unwrap(),
                                        Value::from(v9pkt.header.source_id),
                                    );
                                    pkt.insert(
                                        "sequence_number".parse().unwrap(),
                                        Value::from(v9pkt.header.sequence_number),
                                    );

                                    for (field_name, field_value) in pkts.values() {
                                        let value = field_value.clone();
                                        pkt.insert(
                                            remove_quotes(
                                                serde_json::to_string(&field_name).unwrap(),
                                            ),
                                            FormattedV9FieldValue(value).stringify(),
                                        );
                                    }
                                    packets.push(pkt);
                                }
                            }
                        }
                    }
                }
                /*
                NetflowPacketResult::V7(v7pkt) => {}
                NetflowPacketResult::V5(v5pkt) => {}
                NetflowPacketResult::IPFix(v5pkt) => {}
                */
                _ => {}
            }
        }

        if all_done {
            src.clear();
        }

        if packets.is_empty() {
            Ok(None) // Not enough data for a complete packet yet
        } else {
            Ok(Some(Bytes::from(json!(packets).to_string())))
        }
    }
}

#[derive(Debug)]
struct FormattedV9FieldValue(FieldValue);

impl FormattedV9FieldValue {
    pub fn stringify(self) -> Value {
        match self.0 {
            FieldValue::String(s) => Value::from(s),
            FieldValue::DataNumber(d) => Value::from(usize::from(d)),
            FieldValue::Float64(f) => Value::from(f),
            FieldValue::Duration(d) => Value::from(d.as_secs()),
            FieldValue::Ip4Addr(ip) => Value::from(ip.to_string()),
            FieldValue::Ip6Addr(ip) => Value::from(ip.to_string()),
            FieldValue::MacAddr(mac) => Value::from(mac.to_string()),
            FieldValue::ProtocolType(proto) => {
                Value::from(remove_quotes(serde_json::to_string(&proto).unwrap()))
            }
            FieldValue::Vec(v) => Value::from(base64::encode(v)),
            _ => Value::from(""),
        }
    }
}

fn remove_quotes(s: String) -> String {
    let mut result = s.to_string();
    if result.starts_with('"') || result.starts_with('\'') {
        result = result[1..].to_string(); // Remove first character
    }
    if result.ends_with('"') || result.ends_with('\'') {
        result.pop(); // Remove last character
    }
    result
}
