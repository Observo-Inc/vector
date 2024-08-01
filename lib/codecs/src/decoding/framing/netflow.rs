use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex};

use byteorder::{ByteOrder, NetworkEndian};
use bytes::BytesMut;
use bytes::{Buf, Bytes};
use netflow_parser::variable_versions::common::FieldValue;
use netflow_parser::variable_versions::v9::V9;
use netflow_parser::{NetflowPacketResult, NetflowParser};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_util::codec::{Decoder, LinesCodecError};
use tracing::warn;
use vrl::core::Value;

use crate::decoding::BoxedFramingError;
use vector_config::configurable_component;

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

    fn insert_header_fields(v9pkt: V9) -> BTreeMap<String, Value> {
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
        pkt
    }
}

pub const NETFLOW_V9_VERSION: u16 = 9;
impl Decoder for NetflowDecoder {
    type Item = Bytes; // Output is json as bytes
    type Error = BoxedFramingError; // Or a custom error type

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        //We can do elaborate error handling here but it will not help much as the underlying protocol is broken
        if src.len() < 20 {
            return Ok(None);
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
                    for flowset in &v9pkt.flowsets {
                        if let Some(templates) = &flowset.body.templates {
                            for tmpl in templates {
                                let mut pkt = Self::insert_header_fields(v9pkt.clone());
                                let mut fields: Vec<BTreeMap<String, Value>> = Vec::new();
                                for tmpl in &tmpl.fields {
                                    let mut field: BTreeMap<String, Value> = BTreeMap::new();
                                    field.insert(
                                        "field_type_number".parse().unwrap(),
                                        Value::from(tmpl.field_type_number),
                                    );
                                    field.insert(
                                        "field_length".parse().unwrap(),
                                        Value::from(tmpl.field_length),
                                    );
                                    field.insert(
                                        "field_type".parse().unwrap(),
                                        Value::from(remove_quotes(
                                            serde_json::to_string(&tmpl.field_type).unwrap(),
                                        )),
                                    );
                                    fields.push(field)
                                }
                                pkt.insert("template_id".parse().unwrap(), Value::from(tmpl.template_id));
                                pkt.insert("template_field_count".parse().unwrap(), Value::from(tmpl.field_count));
                                pkt.insert("fields".parse().unwrap(), Value::from(fields));
                                pkt.insert("template_type".parse().unwrap(), Value::from("template"));
                                packets.push(pkt);
                            }
                        }
                        if let Some(data) = &flowset.body.data {
                            if flowset.header.flow_set_id > 255 {
                                for pkts in &data.data_fields {
                                    let mut pkt = Self::insert_header_fields(v9pkt.clone());
                                    for k in pkts.keys() {
                                        if let Some((field_name, field_value)) = pkts.get(k) {
                                            let value = field_value.clone();
                                            pkt.insert(
                                                remove_quotes(
                                                    serde_json::to_string(&field_name).unwrap(),
                                                ),
                                                FormattedV9FieldValue(value).stringify(),
                                            );
                                        }
                                    }
                                    pkt.insert("template_type".parse().unwrap(), Value::from("data"));
                                    packets.push(pkt);
                                }
                            }
                        }
                        if let Some(_data) = &flowset.body.options_data {
                            let mut pkt = Self::insert_header_fields(v9pkt.clone());
                            pkt.insert("template_type".parse().unwrap(), Value::from("options_data"));
                            packets.push(pkt);
                        }
                        if let Some(_data) = &flowset.body.options_templates {
                            let mut pkt = Self::insert_header_fields(v9pkt.clone());
                            pkt.insert("template_type".parse().unwrap(), Value::from("options_templates"));
                            packets.push(pkt);
                        }
                        if let Some(_data) = &flowset.body.unparsed_data {
                            let mut pkt = Self::insert_header_fields(v9pkt.clone());
                            pkt.insert("template_type".parse().unwrap(), Value::from("unparsed_data"));
                            packets.push(pkt);
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

#[cfg(test)]
mod tests {
    use parquet::data_type::AsBytes;

    use super::*;

    fn test_data_decoder(base64_string: &str) -> Option<Bytes> {
        let mut input = BytesMut::from(
            base64::decode(base64_string)
                .expect("should decode")
                .as_bytes(),
        );
        let mut decoder = NetflowDecoder::new();
        let res = decoder.decode(&mut input).expect("Should not fail");
        println!("{:?}", res.clone().unwrap());
        res
    }

    // to generate test functions
    // ls netflow9_* | xargs -S65999 -I{} bash -c 'echo -e "#[test] \n fn test_data_decoder_$(echo "{}" | sed "s/.dat//g")() { \n let data = \"" && /opt/homebrew/bin/gbase64 -w 0 {} && echo -e "\";\n let res = test_data_decoder(data); \n assert_eq!(res.is_some(), true) }"'
    #[test]
    fn test_data_decoder_netflow9_cisco_asr1001x_tpl259() {
        let data = "AAkAGpylMkVZ29qLAA4IAQAAAgAAAABEAQMADwAIAAQADAAEAAUAAQAEAAEABwACAAsAAgAKAAQAXwAEAA8ABAAOAAQAPQABAAEABAACAAQAmAAIAJkACAEDBWQKb2/yCgxkDQAGzNzP4gAAAAQNAAUeCgoFZAAAABABAAADxQAAAAcAAAFfAs123QAAAV8CzXc7CgoEHQpkaVUAEQChoxIAAAAQAwAAoQoKA3IAAAAEAAAAARwAAAABAAABXwLNdt4AAAFfAs123goMZA0Kb2/yAAbP4szcAAAAEA0ABR4KCgNyAAAABAAAAAKeAAAABgAAAV8CzXbfAAABXwLNdzMKDGjvCgoLFbgGBrjwAAAAABANAABACgoDcgAAAAQAAAAAUAAAAAIAAAFfAs124AAAAV8CzXcQCgoLFQoMaO+4BvAABrgAAAAEDQAAQAoKBWQAAAAQAQAAAFAAAAACAAABXwLNduAAAAFfAs13DgpkZS0KD4NiSBEANfuQAAAABAMAADUKCgU+AAAAEAEAAABlAAAAAQAAAV8CzXbgAAABXwLNduAKZGUrCgxpF0gRAAAAAAAAAAQDAAcUCgoFZAAAABABAAAEbgAAAA4AAAFfAs124AAAAV8CzXckHw1HBwoLH2wABgG7yfwAAAAEDQACBgoKBR4AAAAQAQAAAO0AAAAEAAABXwLNduEAAAFfAs128AoLFTwKZGlWABEAoeXaAAAAEAMAAKEKCgNyAAAABAAAAABbAAAAAQAAAV8CzXbiAAABXwLNduIKDFxmrNkLBQAGxk4BuwAAABANAAHOCgoDcgAAAAQAAAAAKQAAAAEAAAFfAs124gAAAV8CzXbiCmRpVgoLFTxgEeXbAKEAAAAEAwAAoQoKBR0AAAAQAQAAAG8AAAABAAABXwLNduMAAAFfAs124woKBOoKZGlVABEAoaGHAAAAEAMAAKEKCgNyAAAABAAAAASMAAAABAAAAV8CzXbkAAABXwLNdwcKDGpTCgoLFbgGBrjwAAAAABANAABACgoDcgAAAAQAAAAAUAAAAAIAAAFfAs125AAAAV8CzXcArNkLBQoMXGYABgG7xk4AAAAEDQABzgoKBaIAAAAQAQAAADQAAAABAAABXwLNduQAAAFfAs125AoKCxUKDGpTuAbwAAa4AAAABA0AAEAKCgVkAAAAEAEAAABQAAAAAgAAAV8CzXblAAABXwLNdv0KDFFWSsmBHQAG5SEBuwAAABANAAHFCgoDcgAAAAQAAAAMEAAAAAoAAAFfAs125gAAAV8CzXdvCg55YgoMZA0ABsP+AYUAAAAQDQAB2QoKBWQAAAAQAAAAFLoAAAAYAAABXwLNducAAAFfAs13cgoLFTwKZGlWABEAoeXbAAAAEAMAAKEKCgNyAAAABAAAAAB0AAAAAQAAAV8CzXbpAAABXwLNdukKDGQNCg55YgAGAYXD/gAAABANAAHZCgoFGQAAABAAAABY7AAAAB4AAAFfAs126QAAAV8CzXd0CgxmfQoKCxW4Bga48AMAAAAQDQAAQAoKA3IAAAAEAAAAAFAAAAACAAABXwLNduoAAAFfAs13KApkaVYKCxU8YBHl3AChAAAABAMAAKEKCgUdAAAAEAEAAABLAAAAAQAAAV8CzXbqAAABXwLNduoKCgsVCgxmfbgG8AMGuAAAAAQNAABACgoFZAAAABABAAAAUAAAAAIAAAFfAs126gAAAV8CzXcmCmRpVQoKBJdgEZGRAKEAAAAEAwAAoQoKBZYAAAAQAQAAAKAAAAACAAABXwLNdusAAAFfAs129goOGVAR/Rj9ABHz2wB7AAAAEAMAAHsKCgNyAAAABAAAAABMAAAAAQAAAV8CzXbrAAABXwLNdusKDJYNCmRlKwAG8WDABAAAABANAAHZCgoDcgAAAAQAAAAFPAAAAAIAAAFfAs127AAAAV8CzXcUAA==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_0length_fields_tpla() {
        let data = "AAkAAgA/tYlYXH9jBgEAAQAAAAAAAAC0AQAAFQAIAAQADAAEAAoAAgAOAAIAAgAEAAEABAAYAAQAFwAEABYABAAVAAQABwACAAsAAgAGAAEABAABAAkAAQANAAEAPQABACcAAQAAAAAAAAAAAAAAAAEBABUAGwAQABwAEAAKAAIADgACAAIABAABAAQAGAAEABcABAAWAAQAFQAEAAcAAgALAAIABgABAAQAAQAdAAEAHgABAD0AAQAnAAEAAAAAAAAAAAAAAAABAAHQ7///+sCoAVAAAwACAAAAAAAAAAAAAAAAAAAAAAA/DrwAPw68AAAAAAACICABAsCoAVDv///6AAIAAwAAAAAAAAAAAAAAAQAAACAAPw68AD8OvAAAAAAAAiAgAQHv///6wKgBXwADAAIAAAAAAAAAAAAAAAAAAAAAAD8bHgA/Gx4AAAAAAAIgIAACwKgBX+////oAAgADAAAAAQAAACAAAAAAAAAAAAA/Gx4APxseAAAAAAACICAAAe////rAqAFfAAMAAgAAAAAAAAAAAAAAAAAAAAAAPxseAD8bHgAAAAAAAiAgAQLAqAFf7///+gACAAMAAAAAAAAAAAAAAAEAAAAgAD8bHgA/Gx4AAAAAAAIgIAEB7///+sCoASEAAwACAAAAAAAAAAAAAAAAAAAAAAA/G4IAPxuCAAAAAAACICAAAsCoASHv///6AAIAAwAAAAEAAAAgAAAAAAAAAAAAPxuCAD8bggAAAAAAAiAgAAHv///6wKgBIQADAAIAAAAAAAAAAAAAAAAAAAAAAD8bggA/G4IAAAAAAAIgIAECwKgBIe////oAAgADAAAAAAAAAAAAAAABAAAAIAA/G4IAPxuCAAAAAAACICABAQ==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_1941k9() {
        let data = "AAkAHgyInrhZ08LrAAY0AAAAAAAAAABEAQAADwAIAAQADAAEAAoABAAHAAIACwACAAUAAQAEAAEABgABAD0AAQDzAAIAOAAGAA8ABAABAAQAAgAEAF8ABAEABQDAqABvPtnBAQAAABGRtQA1ABEAAAAA7B9yEZ/BAAAAAAAAAEsAAAABBQAASMCoAG8+2cFBAAAAEeQrADUAEQAAAADsH3IRn8EAAAAAAAAASwAAAAEFAABIwKgAbz7ZwQEAAAARkx0ANQARAAAAAOwfchGfwQAAAAAAAABLAAAAAQUAAEjAqABvPtnBQQAAABHrNAA1ABEAAAAA7B9yEZ/BAAAAAAAAAEsAAAABBQAASJ5VOnPAqAOOAAAACxRmkkowBh0BA2gAIwQY70DAqAOOAAADxAAAAAoFAAABwKgAWNg61MMAAAAR8DIBuwARAAAAAKTRjOkwLG2m2F0AAAq8AAAACAUAAELYOtTDwKgAWAAAAAsBu/AyMBEAAQNoACMEGO9AwKgAWAAAB+cAAAAJBQAAAcCoAcnYOslqAAAAEcR7AbsABhgAAACYAaefjV9tpthdAAAIhAAAAAkFAAAB2DrJasCoAckAAAALAbvEezAGGAEDaAAjBBjvQMCoAckAAAK8AAAACQUAABA07CGjwKgCdgAAAAsBu++pMAYYAQNoACMEGO9AwKgCdgAAAKEAAAACBQAAEMCoAyI02ILtAAAAEfDqAbsABhsAAAAcXPIHDyptpthdAAAG5AAAABUFAAAQ0cUDE8CoAyIAAAALAbvw6DAGHwEDaAAjBBjvQMCoAyIAADXzAAAAHgUAABA02ILtwKgDIgAAAAsBu/DqMAYbAQNoACMEGO9AwKgDIgAAEm0AAAAQBQAAEMCoAJ2s2RfoAAAAEcgJAbsABhoAAACwNJUN0l1tpthdAAAJcwAAAA0FAAAQrNkX6MCoAJ0AAAALAbvICTAGGgEDaAAjBBjvQMCoAJ0AABWvAAAACgUAABBrFeiuwKgDsgAAAAsBu7IQMAYZAQNoACMEGO9AwKgDsgAAALsAAAADBQAAEMCoA7JrFeiuAAAAEbIQAbsABhEAAADc78pM2ldtpthdAAAAaAAAAAIFAAAQwKgCdl8AkfIAAAAR+ukIrgAGGwAAAHAYi1zJtW2m2F0AAA/SAAAASAUAAAFfAJHywKgCdgAAAAsIrvrpMAYbAQNoACMEGO9AwKgCdgAADocAAABIBQAAAcCoAE8XBWRCAAAAEdQDAbsABhoAAACMKTd6KMBtpthdAAAFegAAABAFAAAQwKgATxcFZEIAAAAR1AQBuwAGGgAAAIwpN3oowG2m2F0AAAYCAAAAEQUAABAXBWRCwKgATwAAAAsBu9QEMAYaAQNoACMEGO9AwKgATwAAMsoAAAAOBQAAEKr7tA/AqAA9AAAACwG73q8wBhgBA2gAIwQY70DAqAA9AAAEqgAAAAQFAAAQwKgAPar7tA8AAAAR3q8BuwAGGAAAAJBhrnbl6W2m2F0AAAKqAAAAAgUAABDAqAMiSnd3VAAAABHw/gG7AAYaAAAAHFzyBw8qbabYXQAABwwAAAALBQAAELk82hPAqAOOAAAACwG76EMwBhoBA2gAIwQY70DAqAOOAAASpgAAAAkFAAABwKgDyLk82g8AAAAR++0BuwAGGAAAABggMrsdYm2m2F0AAACHAAAAAgUAAAG5PNoPwKgDyAAAAAsBu/vtMAYYAQNoACMEGO9AwKgDyAAAAIcAAAACBQAAEMCoAF+pLdb2AAAAEYjtFGYABhgAAACgOfdNSdVtpthdAAAAwgAAAAMFAAAB";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_asa_1a() {
        let data = "AAkADgAfgP1WF41HAAAClgAAAAABCQWYAAAhNMCoDgEAAAADAgICC0SNAAIBAADAqA4BAgICCwAARI0CB+kAAAFQS//X3wAAADgAAAFQS//P8Q+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhNcCoFxZEjQACpKQlCwAAAAMBCADAqBcWpKQlC0SNAAACB+kAAAFQS//aIwAAADgAAAFQS//SSQ+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhNqSkJQsAAAADwKgXFkSNAAIBAACkpCULwKgXFgAARI0CB+kAAAFQS//aSwAAADgAAAFQS//SUw+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhN8CoFxRFjQACpKQlCwAAAAMBCADAqBcUpKQlC0WNAAACB+kAAAFQS//bEwAAADgAAAFQS//TLw+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhOKSkJQsAAAADwKgXFEWNAAIBAACkpCULwKgXFAAARY0CB+kAAAFQS//bHQAAADgAAAFQS//TOQ+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhOcCoDgtFjQADAgICCwAAAAIBCADAqA4LAgICC0WNAAACB+kAAAFQS//b2wAAADgAAAFQS//T7Q+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhOgICAgsAAAACwKgOC0WNAAMBAAACAgILwKgOCwAARY0CB+kAAAFQS//b7wAAADgAAAFQS//T9w+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhOwICAgtFjQACwKgOAQAAAAMBCAACAgILwKgOAUWNAAACB+kAAAFQS//b7wAAADgAAAFQS//UAQ+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhPMCoDgEAAAADAgICC0WNAAIBAADAqA4BAgICCwAARY0CB+kAAAFQS//b7wAAADgAAAFQS//UCw+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhTaSkJQsAAAADwKgXAQAAAAIBAwOkpCULwKgXAQAAAAACB+AAAAFQS//eZQAAAKAAAAFQS//eZQ+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhPcCoFxZGjQACpKQlCwAAAAMBCADAqBcWpKQlC0aNAAACB+kAAAFQS//eZQAAADgAAAFQS//WgQ+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhPqSkJQsAAAADwKgXFkaNAAIBAACkpCULwKgXFgAARo0CB+kAAAFQS//eeQAAADgAAAFQS//Wiw+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhP8CoFxRGjQACpKQlCwAAAAMBCADAqBcUpKQlC0aNAAACB+kAAAFQS//fQQAAADgAAAFQS//XXQ+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhQKSkJQsAAAADwKgXFEaNAAIBAACkpCULwKgXFAAARo0CB+kAAAFQS//fVQAAADgAAAFQS//XZw+Of/P8GgMPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_asa_1_tpl() {
        let data = "AAkADQAfesRWF41FAAAClQAAAAAAAAPgAQAAFQCUAAQACAAEAAcAAgAKAAIADAAEAAsAAgAOAAIABAABALAAAQCxAAGcQQAEnEIABJxDAAKcRAACnEUAAYDqAAIBQwAIAFUABIDoAAyA6QAMnEAAFAEBABUAlAAEAAgABAAHAAIACgACAAwABAALAAIADgACAAQAAQCwAAEAsQABnEEABJxCAAScQwACnEQAApxFAAGA6gACAUMACABVAASA6AAMgOkADJxAAEEBAgARAJQABAAbABAABwACAAoAAgAcABAACwACAA4AAgAEAAEAsgABALMAAZxFAAGA6gACAUMACABVAASA6AAMgOkADJxAABQBAwARAJQABAAbABAABwACAAoAAgAcABAACwACAA4AAgAEAAEAsgABALMAAZxFAAGA6gACAUMACABVAASA6AAMgOkADJxAAEEBBAASAAgABAAHAAIACgACAAwABAALAAIADgACAAQAAQCwAAEAsQABnEEABJxCAAScQwACnEQAApxFAAGA6gACAUMACIDoAAyA6QAMAQUADgAIAAQABwACAAoAAgAMAAQACwACAA4AAgAEAAEAsAABALEAAZxFAAGA6gACAUMACIDoAAyA6QAMAQYADgAbABAABwACAAoAAgAcABAACwACAA4AAgAEAAEAsgABALMAAZxFAAGA6gACAUMACIDoAAyA6QAMAQcAEgCUAAQACAAEAAcAAgAKAAIADAAEAAsAAgAOAAIABAABALAAAQCxAAGcQQAEnEIABJxDAAKcRAACnEUAAYDqAAIBQwAIAFUABAEIAA4AlAAEABsAEAAHAAIACgACABwAEAALAAIADgACAAQAAQCyAAEAswABnEUAAYDqAAIBQwAIAFUABAEJABYAlAAEAAgABAAHAAIACgACAAwABAALAAIADgACAAQAAQCwAAEAsQABnEEABJxCAAScQwACnEQAApxFAAGA6gACAUMACABVAAQAmAAIgOgADIDpAAycQAAUAQoAFgCUAAQACAAEAAcAAgAKAAIADAAEAAsAAgAOAAIABAABALAAAQCxAAGcQQAEnEIABJxDAAKcRAACnEUAAYDqAAIBQwAIAFUABACYAAiA6AAMgOkADJxAAEEBCwASAJQABAAbABAABwACAAoAAgAcABAACwACAA4AAgAEAAEAsgABALMAAZxFAAGA6gACAUMACABVAAQAmAAIgOgADIDpAAycQAAUAQwAEgCUAAQAGwAQAAcAAgAKAAIAHAAQAAsAAgAOAAIABAABALIAAQCzAAGcRQABgOoAAgFDAAgAVQAEAJgACIDoAAyA6QAMnEAAQQ==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_asa_2a() {
        let data = "AAkAEywSgQ5XkNMtAAAAHwAAAAABBwG4LEaHfcCoAALxTwADwKgAEQBQAAQGAADAqAACwKgAEfFPAFACB+4AAAFWDbjYNwAAAFEAAAL7AAABVg241/ssRod+wKgAAvFQAAPAqAARAFAABAYAAMCoAALAqAAR8VAAUAUH7gAAAVYNuNhLAAAAUQAAGD8AAAFWDbjX+yxGh37AqAAC8VAAA8CoABEAUAAEBgAAwKgAAsCoABHxUABQAgfuAAABVg242EsAAABRAAAYPwAAAVYNuNf7LEaHI8CoAAHdOwADwKgAEgBQAAQGAADAqAABwKgAEt07AFAFB+4AAAFWDbjYmwAAAFEAACNzAAABVg241hssRocjwKgAAd07AAPAqAASAFAABAYAAMCoAAHAqAAS3TsAUAIH7gAAAVYNuNibAAAAUQAAI3MAAAFWDbjWGyxGh3vAqAAC8U0AA8CoABEAUAAEBgAAwKgAAsCoABHxTQBQBQfuAAABVg242OEAAABRAAAVoAAAAVYNuNf7LEaHe8CoAALxTQADwKgAEQBQAAQGAADAqAACwKgAEfFNAFACB+4AAAFWDbjY4QAAAFEAABWgAAABVg241/sAAAEAAGgsRoe9wKgAAd1JAAPAqAASAFAABAYAAMCoAAHAqAAS3UkAUAEAAAAAAVYNuNmpAAABVg242ak+3N5JCqYqw6iip2sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQcAgCxGh73AqAAB3UkAA8CoABIAUAAEBgAAwKgAAcCoABLdSQBQBQfuAAABVg242gMAAABFAAA3YwAAAVYNuNmpLEaHvcCoAAHdSQADwKgAEgBQAAQGAADAqAABwKgAEt1JAFACB+4AAAFWDbjaAwAAAEUAADdjAAABVg242akBAABoLEaIucCoAALxUQADwKgAEQBQAAQGAADAqAACwKgAEfFRAFABAAAAAAFWDbjgGwAAAVYNuOAbPtzeSQqmKsNW6FEuAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEHAIAsRoi5wKgAAvFRAAPAqAARAFAABAYAAMCoAALAqAAR8VEAUAUH7gAAAVYNuOB1AAAARQAAN2IAAAFWDbjgGyxGiLnAqAAC8VEAA8CoABEAUAAEBgAAwKgAAsCoABHxUQBQAgfuAAABVg244HUAAABFAAA3YgAAAVYNuOAbAQAAaCxGiTnAqAAB3UoAA8CoABEAUAAEBgAAwKgAAcCoABHdSgBQAQAAAAABVg244wkAAAFWDbjjCT7c3kkKpirDVuhRLgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBwCALEaJOcCoAAHdSgADwKgAEQBQAAQGAADAqAABwKgAEd1KAFAFB+4AAAFWDbjjlQAAAEsAAANxAAABVg244wksRok5wKgAAd1KAAPAqAARAFAABAYAAMCoAAHAqAAR3UoAUAIH7gAAAVYNuOOVAAAASwAAA3EAAAFWDbjjCQEAAGgsRol/wKgAAd1LAAPAqAASAFAABAYAAMCoAAHAqAAS3UsAUAEAAAAAAVYNuOVrAAABVg245Ws+3N5JCqYqw6iip2sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQcAgCxGiX/AqAAB3UsAA8CoABIAUAAEBgAAwKgAAcCoABLdSwBQBQfuAAABVg245c8AAABFAAA3YgAAAVYNuOVrLEaJf8CoAAHdSwADwKgAEgBQAAQGAADAqAABwKgAEt1LAFACB+4AAAFWDbjlzwAAAEUAADdiAAABVg245Ws=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_asa_2_tpl_26x() {
        let data = "AAkAECwTuoBXkNN9AAAASgAAAAAAAAVYAQAAFQCUAAQACAAEAAcAAgAKAAIADAAEAAsAAgAOAAIABAABALAAAQCxAAEA4QAEAOIABADjAAIA5AACAOkAAYDqAAIBQwAIAJgACIDoAAyA6QAMnEAAFAEBABUAlAAEAAgABAAHAAIACgACAAwABAALAAIADgACAAQAAQCwAAEAsQABAOEABADiAAQA4wACAOQAAgDpAAGA6gACAUMACACYAAiA6AAMgOkADJxAAEEBAgAVAJQABAAbABAABwACAAoAAgAcABAACwACAA4AAgAEAAEAsgABALMAAQEZABABGgAQAOMAAgDkAAIA6QABgOoAAgFDAAgAmAAIgOgADIDpAAycQAAUAQMAFQCUAAQAGwAQAAcAAgAKAAIAHAAQAAsAAgAOAAIABAABALIAAQCzAAEBGQAQARoAEADjAAIA5AACAOkAAYDqAAIBQwAIAJgACIDoAAyA6QAMnEAAQQEEABIACAAEAAcAAgAKAAIADAAEAAsAAgAOAAIABAABALAAAQCxAAEA4QAEAOIABADjAAIA5AACAOkAAYDqAAIBQwAIgOgADIDpAAwBBQAOAAgABAAHAAIACgACAAwABAALAAIADgACAAQAAQCwAAEAsQABAOkAAYDqAAIBQwAIgOgADIDpAAwBBgAOABsAEAAHAAIACgACABwAEAALAAIADgACAAQAAQCyAAEAswABAOkAAYDqAAIBQwAIgOgADIDpAAwBBwAUAJQABAAIAAQABwACAAoAAgAMAAQACwACAA4AAgAEAAEAsAABALEAAQDhAAQA4gAEAOMAAgDkAAIA6QABgOoAAgFDAAgA5wAEAOgABACYAAgBCAAUAJQABAAbABAABwACAAoAAgAcABAACwACAA4AAgAEAAEAsgABALMAAQEZABABGgAQAOMAAgDkAAIA6QABgOoAAgFDAAgA5wAEAOgABACYAAgBCQAXAJQABAAIAAQABwACAAoAAgAMAAQACwACAA4AAgAEAAEAsAABALEAAQDhAAQA4gAEAOMAAgDkAAIA6QABgOoAAgFDAAgA5wAEAOgABACYAAiA6AAMgOkADJxAABQBCgAXAJQABAAIAAQABwACAAoAAgAMAAQACwACAA4AAgAEAAEAsAABALEAAQDhAAQA4gAEAOMAAgDkAAIA6QABgOoAAgFDAAgA5wAEAOgABACYAAiA6AAMgOkADJxAAEEBCwAXAJQABAAbABAABwACAAoAAgAcABAACwACAA4AAgAEAAEAsgABALMAAQEZABABGgAQAOMAAgDkAAIA6QABgOoAAgFDAAgA5wAEAOgABACYAAiA6AAMgOkADJxAABQBDAAXAJQABAAbABAABwACAAoAAgAcABAACwACAA4AAgAEAAEAsgABALMAAQEZABABGgAQAOMAAgDkAAIA6QABgOoAAgFDAAgA5wAEAOgABACYAAiA6AAMgOkADJxAAEEBDQAVAJQABAAIAAQABwACAAoAAgAMAAQACwACAA4AAgAEAAEAsAABALEAAQEZABABGgAQAOMAAgDkAAIA6QABgOoAAgFDAAgAmAAIgOgADIDpAAycQAAUAQ4AFQCUAAQACAAEAAcAAgAKAAIADAAEAAsAAgAOAAIABAABALAAAQCxAAEBGQAQARoAEADjAAIA5AACAOkAAYDqAAIBQwAIAJgACIDoAAyA6QAMnEAAQQEPABUAlAAEABsAEAAHAAIACgACABwAEAALAAIADgACAAQAAQCyAAEAswABAOEABADiAAQA4wACAOQAAgDpAAGA6gACAUMACACYAAiA6AAMgOkADJxAABQ=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_asa_2_tpl_27x() {
        let data = "AAkADiwTuoBXkNN9AAAASwAAAAAAAASoARAAFQCUAAQAGwAQAAcAAgAKAAIAHAAQAAsAAgAOAAIABAABALIAAQCzAAEA4QAEAOIABADjAAIA5AACAOkAAYDqAAIBQwAIAJgACIDoAAyA6QAMnEAAQQERABIAGwAQAAcAAgAKAAIAHAAQAAsAAgAOAAIABAABALIAAQCzAAEBGQAQARoAEADjAAIA5AACAOkAAYDqAAIBQwAIgOgADIDpAAwBEgASAAgABAAHAAIACgACAAwABAALAAIADgACAAQAAQCwAAEAsQABARkAEAEaABAA4wACAOQAAgDpAAGA6gACAUMACIDoAAyA6QAMARMAEgAIAAQABwACAAoAAgAMAAQACwACAA4AAgAEAAEAsAABALEAAQDhAAQBGgAQAOMAAgDkAAIA6QABgOoAAgFDAAiA6AAMgOkADAEUABIAGwAQAAcAAgAKAAIAHAAQAAsAAgAOAAIABAABALIAAQCzAAEA4QAEAOIABADjAAIA5AACAOkAAYDqAAIBQwAIgOgADIDpAAwBFQASABsAEAAHAAIACgACABwAEAALAAIADgACAAQAAQCyAAEAswABARkAEADiAAQA4wACAOQAAgDpAAGA6gACAUMACIDoAAyA6QAMARYAFACUAAQACAAEAAcAAgAKAAIADAAEAAsAAgAOAAIABAABALAAAQCxAAEBGQAQARoAEADjAAIA5AACAOkAAYDqAAIBQwAIAOcABADoAAQAmAAIARcAFACUAAQACAAEAAcAAgAKAAIADAAEAAsAAgAOAAIABAABALAAAQCxAAEA4QAEARoAEADjAAIA5AACAOkAAYDqAAIBQwAIAOcABADoAAQAmAAIARgAFACUAAQAGwAQAAcAAgAKAAIAHAAQAAsAAgAOAAIABAABALIAAQCzAAEA4QAEAOIABADjAAIA5AACAOkAAYDqAAIBQwAIAOcABADoAAQAmAAIARkAFACUAAQAGwAQAAcAAgAKAAIAHAAQAAsAAgAOAAIABAABALIAAQCzAAEBGQAQAOIABADjAAIA5AACAOkAAYDqAAIBQwAIAOcABADoAAQAmAAIARoAFwCUAAQACAAEAAcAAgAKAAIADAAEAAsAAgAOAAIABAABALAAAQCxAAEBGQAQARoAEADjAAIA5AACAOkAAYDqAAIBQwAIAOcABADoAAQAmAAIgOgADIDpAAycQAAUARsAFwCUAAQACAAEAAcAAgAKAAIADAAEAAsAAgAOAAIABAABALAAAQCxAAEBGQAQARoAEADjAAIA5AACAOkAAYDqAAIBQwAIAOcABADoAAQAmAAIgOgADIDpAAycQABBARwAFwCUAAQAGwAQAAcAAgAKAAIAHAAQAAsAAgAOAAIABAABALIAAQCzAAEA4QAEAOIABADjAAIA5AACAOkAAYDqAAIBQwAIAOcABADoAAQAmAAIgOgADIDpAAycQAAUAR0AFwCUAAQAGwAQAAcAAgAKAAIAHAAQAAsAAgAOAAIABAABALIAAQCzAAEA4QAEAOIABADjAAIA5AACAOkAAYDqAAIBQwAIAOcABADoAAQAmAAIgOgADIDpAAycQABB";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_asr9ka256() {
        let data = "AAkAE2WdGn1YRo5sAXXKjwAACIEBAAVcwcS+QwAAAEpUZW5HaWdFMF8wXzFfMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAAEtUZW5HaWdFMF8wXzFfMQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAAExUZW5HaWdFMF8wXzFfMgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAADZHaWdhYml0RXRoZXJuZXQwXzBfMF8wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAADdHaWdhYml0RXRoZXJuZXQwXzBfMF8xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAADhHaWdhYml0RXRoZXJuZXQwXzBfMF8yAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAADpHaWdhYml0RXRoZXJuZXQwXzBfMF80AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAADtHaWdhYml0RXRoZXJuZXQwXzBfMF81AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAADxHaWdhYml0RXRoZXJuZXQwXzBfMF82AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAAEJHaWdhYml0RXRoZXJuZXQwXzBfMF8xMgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAAFZUZW5HaWdFMF8xXzBfMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAAFdUZW5HaWdFMF8xXzBfMQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAAFhUZW5HaWdFMF8xXzBfMgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAAKJCdW5kbGUtRXRoZXIyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAAG5UZW5HaWdFMF82XzFfMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAAG9UZW5HaWdFMF82XzFfMQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAAGZUZW5HaWdFMF82XzBfMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAAGdUZW5HaWdFMF82XzBfMQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwcS+QwAAAGhUZW5HaWdFMF82XzBfMgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_asr9ka260() {
        let data = "AAkAFWWcvHFYRo5UAXXGoQAACIEBBAVcAAAAAQAAACgKAAmSCgAfUQAAAG4AAACeZZxHBWWcRwXTAQG7AAAAAAAA+/AKAA4hEBQGEAABQAABYAAAAGAAAAAAAAACAAAAaAoAESoKACMEAAAAVwAAAJ5lnEmIZZxHB46EAbsAAAAAAAD78AoADiEVEAYQAAFAAAFgAAAAYAAAAAAAAAEAAAA0CgAWbwoAIo0AAABoAAAAnmWcRwplnEcKQa4BuwAAAAAAAPvwCgAOIRgQBhEAAUAAAWAAAABgAAAAAAAAAQAAAbMKABc7CgAkqgAAAFYAAACeZZxHDGWcRwwANf0sAAAAAAAA+/EKAA4fGRMRAAABQAABYAAAAGAAAAAAAAABAAADyQoAIkcKABTyAAAAngAAAGplnEcNZZxHDQG7B90AAPvwAAD/ogoAEgUQFQYYAABAAAFgAAAAYAAAAAAAAAIAAABoCgAKhQoAHmYAAABuAAAAnmWcRw1lnEa6ickAUAAAAAAAAPvwCgAOIRAQBhAAAUAAAWAAAABgAAAAAAAAAQAAADQKACUdCgAGGAAAAGYAAACiZZxHEGWcRxAAUN3DAAA7HQAA/5cKAADyGBAGECAAQAABYAAAAGAAAAAAAAABAAACZgoAILAKAAtxAAAAngAAAC5lnEcQZZxHEAG73f4AAPvwAAD/mAoAEmkUEAYYAABAAAFgAAAAYAAAAAAAAAMAABD+CgAMFQoADyYAAABXAAAAnmWcRxFlnDHnAbucjgAAgKYAAPvyCgAOGxgYBhAAAUAAAWAAAABgAAAAAAAAAgAAAhUKAATUCgADbgAAAKIAAABmZZxUB2WcRxLGAwG7AAD/lwAAAEYKABBlEBEGGAABQAABYAAAAGAAAAAAAAFFAAA1XAoAIXoKAAGIAAAAngAAAGhlnG/QZZwiGuW+AFAAAPvxAAAAAAAAAAAVGwYQAABAAAFgAAAAYAAAAAAAAAEAAABZCgAU8goAIkcAAABqAAAAnmWcRxRlnEcUB90BuwAA/6IAAPvwCgAOIRUQBhhgAUAAAWAAAABgAAAAAAAAAQAAA0EKAA0ZCgAPJgAAAFcAAACeZZxHFmWcRxYBu8mlAACApgAA+/IKAA4bGBgGGAABQAABYAAAAGAAAAAAAAACAAAGWQoAGTsKAAISAAAAngAAAG5lnEcYZZxGvwG79AAAAPvwAAD/nQoAEn4QEAYYAABAAAFgAAAAYAAAAAAAAGEAAitoCgAHSQoAG6gAAABWAAAAnmWcdatlnDH+65gB0QAA/5wAAPvwCgAOIRAQBhgAAUAAAWAAAABgAAAAAAAAOgAAC8gKABMyCgAbqQAAAGoAAACeZZxPy2WcRTqGlAPjAAD/twAA+/AKAA4hEhAGEAABQAABYAAAAGAAAAAAAAAVAAB7DAoAHJYKABgNAAAAngAAAGhlnEhZZZxG8AG7wv0AAPvwAAAAAAAAAAAQGQYQAABAAAFgAAAAYAAAAAAAAAMAAAtnCgAavAoAFcgAAACeAAAAV2WcR2ZlnEXsA+HETgAA+/AAAAAAAAAAABAZBhgAAEAAAWAAAABgAAAAAAAABQAAEaIKAB0iCgAPJgAAAEsAAACeZZxtYGWcQf4Bu4yPAAA7QQAA+/IKAA4bGBgGGAABQAABYAAAAGAAAAAAAAABAAABRgoACMgKAAXgAAAAZgAAAKJlnEcdZZxHHVpYydcAAAMVAAD/lwoAAPIQEAYYAABAAAFgAAAAYAAAAAAAAAIAAABwCgAdLgoADyYAAABLAAAAnmWcRx1lnEDqAbvMjAAAO0EAAPvyCgAOGxgYBhIAAUAAAWAAAABgAAAAAAAA";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_asr9k_opttpl256() {
        let data = "AAkAAWWdGn1YRo5sAXXKjgAACIEAAQAYAQAABAAIAAEABAAKAAQAUwBAAAA=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_asr9k_opttpl257() {
        let data = "AAkAAWWdGn1YRo5sAXXKjAAACIEAAQAgAQEABAAQAAEABAAwAAIAMgAEADEAAQBUACAAAA==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_asr9k_opttpl334() {
        let data = "AAkAAWWdGn1YRo5sAXXKiwAACIEAAQAYAU4ABAAIAAEABADqAAQA7AAgAAA=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_asr9k_tpl260() {
        let data = "AAkAAWWcwF9YRo5VAXXHAwAACIEAAABkAQQAFwACAAQAAQAEAAgABAAMAAQACgAEAA4ABAAVAAQAFgAEAAcAAgALAAIAEAAEABEABAASAAQACQABAA0AAQAEAAEABgABAAUAAQA9AAEAWQABADAAAgDqAAQA6wAE";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_asr9k_tpl266() {
        let data = "AAkAAWWcsqJYRo5RAXXGmwAACIEAAABsAQoAGQACAAQAAQAEABsAEAAcABAACgAEAA4ABAAWAAQAFQAEAB8ABABAAAQABwACAAsAAgAQAAQAEQAEAD8AEAAeAAEAHQABAAQAAQAGAAEABQABAD0AAQBZAAEAMAACAOoABADrAAQ=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_nbara262() {
        let data = "AAkABfQeqxBYouWsABcHDgAAAAABBgGZCh4SPgoeE7QBAAABAAAAAQAAAAAAAAgAAAABFwAAUFaRVoYc3w9+w1gAAAAAAAAAAAAAAAAKHhIAAAAAAAAAACwAAAAB9B5qGPQeahgAAAAACh4SPgoeE7QFAAAmAAAAAQAAAACFrAChAAARFwAAUFaRVoYc3w9+w1gAAAAAAAAAoQAAAAAKHhIAAAAAAAAAAGoAAAAB9B5qGPQeahgAAAAACgqsPAoeE7QBAAABAAAAAQAAAAAAAAgAAAABAAAAGBmebAEc3w9+w1gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACwAAAAB9B5sRPQebEQAAAAACgqsPAoeE7QDAAB7AAAAAQAAAAAAewB7AMARADAAGBmebAEc3w9+w1gAAAAAAAAAewAAAAAAAAAAAAAAAAAAAEwAAAAB9B5sjPQebIwAAAAACgqsPAoeE7QFAAAmAAAAAQAAAACw1QChAAARAAAAGBmebAEc3w9+w1gAAAAAAAAAoQAAAAAAAAAAAAAAAAAACuoAAAAk9B5sUPQebJgAAAAA";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_nbar_opttpl260() {
        let data = "AAkAEHYKb6xYouWHAAoB9AAAAAAAAQAaAQQABAAMAAEABABfAAQAYAAYAF4ANwEEBR0KDwFzAQAACGVncAAAAAAAAAAAAAAAAAAAAAAAAAAAAEV4dGVyaW9yIEdhdGV3YXkgUHJvdG9jb2wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKDwFzAQAAL2dyZQAAAAAAAAAAAAAAAAAAAAAAAAAAAEdlbmVyYWwgUm91dGluZyBFbmNhcHN1bGF0aW9uAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKDwFzAQAAAWljbXAAAAAAAAAAAAAAAAAAAAAAAAAAAEludGVybmV0IENvbnRyb2wgTWVzc2FnZQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKDwFzAQAAWGVpZ3JwAAAAAAAAAAAAAAAAAAAAAAAAAEVuaGFuY2VkIEludGVyaW9yIEdhdGV3YXkgUm91dGluZyBQcm90b2NvbAAAAAAAAAAAAAAAAAAKDwFzAQAABGlwaW5pcAAAAAAAAAAAAAAAAAAAAAAAAElQIGluIElQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKDwFzAQAAWW9zcGYAAAAAAAAAAAAAAAAAAAAAAAAAAE9wZW4gU2hvcnRlc3QgUGF0aCBGaXJzdAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKDwFzAQAAAGhvcG9wdAAAAAAAAAAAAAAAAAAAAAAAAElQdjYgSG9wLWJ5LUhvcCBPcHRpb24AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKDwFzAQAAA2dncAAAAAAAAAAAAAAAAAAAAAAAAAAAAEdhdGV3YXktdG8tR2F0ZXdheQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKDwFzAQAABXN0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAFN0cmVhbQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKDwFzAQAAB2NidAAAAAAAAAAAAAAAAAAAAAAAAAAAAENCVAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKDwFzAQAACWlncnAAAAAAAAAAAAAAAAAAAAAAAAAAAENpc2NvIGludGVyaW9yIGdhdGV3YXkgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKDwFzAQAACmJibnJjY21vbgAAAAAAAAAAAAAAAAAAAEJCTiBSQ0MgTW9uaXRvcmluZwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKDwFzAQAAC252cC1paQAAAAAAAAAAAAAAAAAAAAAAAE5ldHdvcmsgVm9pY2UgUHJvdG9jb2wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKDwFzAQAADHB1cAAAAAAAAAAAAAAAAAAAAAAAAAAAAFBVUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKDwFzAQAADWFyZ3VzAAAAAAAAAAAAAAAAAAAAAAAAAEFSR1VTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_nbar_tpl262() {
        let data = "AAkAAfQeLhBYouWMABcG2wAAAAAAAABwAQYAGgAIAAQADAAEAF8ABAAKAAQADgAEAAcAAgALAAIAPQABAAUAAQAEAAEACQABAMMAAQA4AAYAUAAGABAAAgARAAIAtgACALUAAgAPAAQALAAEADAABAABAAQAAgAEABYABAAVAAQANgAE";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_wlc_8510_tpl_262() {
        let data = "AAkABEN0865ZyOW4AAEI5QAAAAEAAQAYAQAABAAIAAEABABfAAQAYABAYW4AAQAYAQIABAAIAAEABE4gAAIAkwAhAGcAAQAYAQMABAAIAAEABAA6AAIAUgAgbmUAAABMAQYAEQAIAAQADAAEAAcAAgALAAIABAABAD0AAQBfAAQBbQAGAW8ABk4gAAIAOgACAAUAAQAWAAQAFQAEAAEACAACAAgBcwAh";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_wlca261() {
        let data = "AAkAAU+roJ5ZS2QyAAAATgAAAAEBBQVcNAKGdcBRwKgUeQ0AAd9UZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADPgAAAAAAAAAUwAAAPZjzIBgNAKGdcBRwKgUeQ0AAd9UZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAADPgAAAAAAAAAUwAAAPZjzIBgNAKGdcBRwKgUeQMAADVUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHlAAAAAAAAAARQAAAPZjzIBgNAKGdcBRwKgUeQMAADVUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAJ/UAAAAAAAAARQAAAPZjzIBgNAKGdcBRwKgUeQMAAIpUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANcAAAAAAAAAAQAAAPZjzIBgNAKGdcBRwKgUeQ0AAAFUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAn5YAAAAAAAAA4QAAAPZjzIBgNAKGdcBRwKgUeQ0AAAFUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAjBoAAAAAAAAAmgAAAPZjzIBgNAKGdcBRwKgUeQMAAFBUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAL/cAAAAAAAAAPwAAAPZjzIBgNAKGdcBRwKgUeQMAAFBUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAapcAAAAAAAAAPQAAAPZjzIBgNAKGdcBRwKgUeQ0AAcVUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACPskAAAAAAAADBQAAAPZjzIBgNAKGdcBRwKgUeQ0AAcVUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAASC+cAAAAAAAAFYwAAAPZjzIBgNAKGdcBRwKgUeQ0AAghUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGnkAAAAAAAAAGgAAAPZjzIBgNAKGdcBRwKgUeQ0AAghUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAIbEAAAAAAAAAGgAAAPZjzIBgNAKGdcBRwKgUeQMAAbtUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlH+kAAAAAAABP0gAAAPZjzIBgNAKGdcBRwKgUeQMAAbtUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAANfpIAAAAAAAACfFgAAAPZjzIBgNAKGdcBRwKgUeQEAAAFUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABnoAAAAAAAAADwAAAPZjzIBgNAKGdcBRwKgUeQEAAAFUZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAA7YAAAAAAAAADgAAAPZjzIBgNAKGdcBRwKgUeQ0AAa9UZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAW0g8AAAAAAAA/EQAAAPZjzIBgNAKGdcBRwKgUeQ0AAa9UZXN0LWVudgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAATTkDgAAAAAAADQcgAAAPZjzIBg";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_cisco_wlc_tpl() {
        let data = "AAkAAk+r9pZZS2RIAAAAUAAAAAEAAQAYAQAABAAIAAEABABfAAQAYABALWcAAAAwAQUACgFtAAYBbgAEAF8ABACTACEAPQABAAEACAACAAgAYgABAMMAAQFvAAY=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_field_layer2segmentida() {
        let data = "AAkAAQBVNIBaXcmeAAASpQAEAAABCgBAwKjIiFBS7SgG8eYBvQAMZgAAAAAAAAAAAAAABwAAAAAAAFT56ABU+ehiAAAAAAAAADQAAAAAAAAAAQAA";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_field_layer2segmentid_tpl() {
        let data = "AAkAAQBVLLBaXcmcAAASoQAEAAAAAABMAQoAEQAIAAQADAAEAAQAAQAHAAIACwACAAUAAQA6AAIBXwAIAAoABADqAAQAPQABABYABAAVAAQAMAABAAEACAACAAgA0gAC";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_fortigate_fortios_521a256() {
        let data =
            "AAkAAQE3sapZbZ+2AAA1SQAAAAEBAAAoAAEAAAABmZAB5wAAAAAAteXWAAAAAAABpVgHCAAPAAAAAQEA";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_fortigate_fortios_521a257() {
        let data = "AAkAAQE3dxJZbZ+nAAA1QwAAAAEBAQA4AAAAAAAAAJgAAAAAAAAAAAAAAAMAAAAAJQ9UpCUPd8zx1gG7AAkAAwbAqGMHHw1XJAAAAA==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_fortigate_fortios_521_tpl() {
        let data = "AAkAAgE37EJZbZ/FAAA1TAAAAAEAAADcAQEADQABAAgAFwAIAAIABAAYAAQAFgAEABUABAAHAAIACwACAAoAAgAOAAIABAABAAgABAAMAAQBAgANAAEACAAXAAgAAgAEABgABAAWAAQAFQAEAAcAAgALAAIACgACAA4AAgAEAAEAGwAQABwAEAEDAAwAAQAIABcACAACAAQAGAAEABYABAAVAAQACgACAA4AAgAgAAIABAABAAgABAAMAAQBBAAMAAEACAAXAAgAAgAEABgABAAWAAQAFQAEAAoAAgAOAAIAIAACAAQAAQAbABAAHAAQAAEALAEAAAQAHAABAAIAKAAIACkACAAqAAgAJAACACUAAgAiAAQAIwABAAA=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_fortigate_fortios_542_appida258_262() {
        let data = "AAkAEQAlHGRa9OmzAAABXgAAAAEBBgBQAAAAAAAAAuwAAAAAAAAC7AAAAAYAAAAGACUW2AAlGHKxRABQAAgAAgYUAAAwRAAAjzQMTEADwKhkl7YyiO8KAAD6AAAAALFEAAAAAAEGAFAAAAAAAAAbJAAAAAAAABskAAAACgAAAAoAJRMOACUXeAG7ruoAAgAIBhQAADBEAACeeAxMQAPQZBG7wKhklwAAAAAKAAD6AACu6gAAAQYAUAAAAAAAAAYwAAAAAAAABjAAAAAOAAAADgAlEw4AJRd4ruoBuwAIAAIGFAAAMEQAAJ54DExAA8CoZJfQZBG7CgAA+gAAAACu6gAAAAABBgBQAAAAAAAAIAkAAAAAAAAgCQAAAAsAAAALACUTaAAlF3gBu8W6AAIACAYUAAAwRAAAnngMTEAD0GQRvcCoZJcAAAAACgAA+gAAxboAAAEGAFAAAAAAAAAGwQAAAAAAAAbBAAAADwAAAA8AJRNoACUXeMW6AbsACAACBhQAADBEAACeeAxMQAPAqGSX0GQRvQoAAPoAAAAAxboAAAAAAQYAUAAAAAAAAARiAAAAAAAABGIAAAAFAAAABQAlE2gAJRUCAFCDfAACAAgGFAAAMEQAAGTzDExAA7L/UwHAqGSXAAAAAAoAAPoAAIN8AAABBgBQAAAAAAAAAsEAAAAAAAACwQAAAAUAAAAFACUTaAAlFQKDfABQAAgAAgYUAAAwRAAAZPMMTEADwKhkl7L/UwEKAAD6AAAAAIN8AAAAAAEGAFAAAAAAAAAEYwAAAAAAAARjAAAABQAAAAUAJRFMACUSvgBQg24AAgAIBhQAADBEAABk8wxMQAOy/1MBwKhklwAAAAAKAAD6AACDbgAAAQYAUAAAAAAAAALCAAAAAAAAAsIAAAAFAAAABQAlEUwAJRK+g24AUAAIAAIGFAAAMEQAAGTzDExAA8CoZJey/1MBCgAA+gAAAACDbgAAAAABAgBEAAAAAAAAAEoAAAAAAAAASgAAAAEAAAABACJTsgAiVAIANc7qAAAAABEUAAAwRAAAAAAOBMMAwKhkb8CoZJYAAAECAEQAAAAAAAAAOgAAAAAAAAA6AAAAAQAAAAEAIlOyACJUAs7qADUAAAAAERQAADBEAAAAAA4EwwDAqGSWwKhkbwAAAQIARAAAAAAAAABKAAAAAAAAAEoAAAABAAAAAQAiU7IAIlQCADXAnwAAAAARFAAAMEQAAAAADgTDAMCoZG/AqGSWAAABAgBEAAAAAAAAADoAAAAAAAAAOgAAAAEAAAABACJTsgAiVALAnwA1AAAAABEUAAAwRAAAAAAOBMMAwKhklsCoZG8AAAECAEQAAAAAAAAELwAAAAAAAAQvAAAABQAAAAUAJQHKACUJrgBQyiIAAAAIBhQAADBEAAAAAA4MwwPAqGRvwKhklgAAAQIARAAAAAAAAAR7AAAAAAAABHsAAAAGAAAABgAlAcoAJQmuyiIAUAAIAAAGFAAAMEQAAAAADgzDA8CoZJbAqGRvAAABAgBEAAAAAAAAB7wAAAAAAAAHvAAAAAYAAAAGACTiigAk8ioAUMohAAAACAYUAAAwRAAAAAAODMMDwKhkb8CoZJYAAAECAEQAAAAAAAAIdAAAAAAAAAh0AAAACAAAAAgAJOKKACTyKsohAFAACAAABhQAADBEAAAAAA4MwwPAqGSWwKhkbwAA";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_fortigate_fortios_542_appid_tpl258_269() {
        let data = "AAkAAwAhMBha9OiyAAABMgAAAAEAAAPMAQIAEQABAAgAFwAIAAIABAAYAAQAFgAEABUABAAHAAIACwACAAoAAgAOAAIABAABAF8ACQBBAAIAWQABAIgAAQAIAAQADAAEAQQAEAABAAgAFwAIAAIABAAYAAQAFgAEABUABAAKAAIADgACACAAAgAEAAEAXwAJAEEAAgBZAAEAiAABAAgABAAMAAQBBgAVAAEACAAXAAgAAgAEABgABAAWAAQAFQAEAAcAAgALAAIACgACAA4AAgAEAAEAXwAJAEEAAgBZAAEAiAABAAgABAAMAAQA4QAEAOIABADjAAIA5AACAQoAFAABAAgAFwAIAAIABAAYAAQAFgAEABUABAAKAAIADgACACAAAgAEAAEAXwAJAEEAAgBZAAEAiAABAAgABAAMAAQA4QAEAOIABADjAAIA5AACAQcAFQABAAgAFwAIAAIABAAYAAQAFgAEABUABAAHAAIACwACAAoAAgAOAAIABAABAF8ACQBBAAIAWQABAIgAAQAIAAQADAAEARkAEAEaABAA4wACAOQAAgELABQAAQAIABcACAACAAQAGAAEABYABAAVAAQACgACAA4AAgAgAAIABAABAF8ACQBBAAIAWQABAIgAAQAIAAQADAAEARkAEAEaABAA4wACAOQAAgEDABEAAQAIABcACAACAAQAGAAEABYABAAVAAQABwACAAsAAgAKAAIADgACAAQAAQBfAAkAQQACAFkAAQCIAAEAGwAQABwAEAEFABAAAQAIABcACAACAAQAGAAEABYABAAVAAQACgACAA4AAgAgAAIABAABAF8ACQBBAAIAWQABAIgAAQAbABAAHAAQAQgAFQABAAgAFwAIAAIABAAYAAQAFgAEABUABAAHAAIACwACAAoAAgAOAAIABAABAF8ACQBBAAIAWQABAIgAAQAbABAAHAAQARkAEAEaABAA4wACAOQAAgEMABQAAQAIABcACAACAAQAGAAEABYABAAVAAQACgACAA4AAgAgAAIABAABAF8ACQBBAAIAWQABAIgAAQAbABAAHAAQARkAEAEaABAA4wACAOQAAgEJABUAAQAIABcACAACAAQAGAAEABYABAAVAAQABwACAAsAAgAKAAIADgACAAQAAQBfAAkAQQACAFkAAQCIAAEAGwAQABwAEADhAAQA4gAEAOMAAgDkAAIBDQAUAAEACAAXAAgAAgAEABgABAAWAAQAFQAEAAoAAgAOAAIAIAACAAQAAQBfAAkAQQACAFkAAQCIAAEAGwAQABwAEADhAAQA4gAEAOMAAgDkAAIAAQAsAQAABAAcAAEAAgAoAAgAKQAIACoACAAkAAIAJQACACIABAAjAAEAAAABACABAQAEABAAAQACAF8ACQBgAEAAXgBAAXQAIAAA";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_h3ca3281() {
        let data = "AAkAEOvuoHVbApBwA5jABQAACwAM0QBUAAAAAAAAArkAAAAAAA+sD+vtQYPr7p8yAAAKZgAABjYKFqYeChajFQoVGY4AAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAAAAYAAAAAAAAYOOvttL7r7p8jAAAKZgAAAe4KFqYMChUDrAoVBwYAAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAAABUAAAAAAAAueOvttK3r7p8dAAAKZgAAC1wKFqYhChayJQoVGcoAAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAAAAMAAAAAAAAEEevtP3Xr7p8QAAAKZgAAAxUKFqYjChRk/QoUEUYAAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAAABQAAAAAAAAGzOvtP3Lr7bSiAAAKZgAABN4KFqYkChSIJAoUEaIAAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAAABAAAAAAAAALtuvtQa/r7bTKAAAKZgAABQUKFqYkChSTHAoUEc4AAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAAACUAAAAAAADZ3evtQb/r7bTLAAAKZgAABPcKFqYcChSNEAoUEbYAAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAACFcAAAAAADFuDuvtQdDr7bTZAAAKZgAABcAKFqYjChSiEQoUE4oAAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAAABQAAAAAAAAWRevtP6rr7bTaAAAKZgAABekKFqYPChSrJAoUE64AAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAACvQAAAAAAEDtJOvtQhHr7bTgAAAKZgAAC5cKFqYCChbQDAoVHUIAAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAAABkAAAAAAACStevtQtzr7bToAAAKZgAACp8KFqYcChbEFQoVHRIAAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAAAEQAAAAAAABcfOvtP+7r7bUeAAAKZgAAC4kKFqYZChbKDwoVHSoAAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAAAB4AAAAAAABZJevtQ5br7qBYAAAKZgAABdQKFqYZChSmGgoUE5oAAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAAAAIAAAAAAAACDuvtQKfr7qBDAAAKZgAAAe4KFqYMChUDdQoVBwYAAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAAANwAAAAAAACBaevttdLr7qA3AAAKZgAABUUKFqYRChaRGgoVGUYAAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAAM0QBUAAAAAAAAAAkAAAAAAAAT5Ovttcfr7qAtAAAKZgAABs8KFqYkChVLJgoVEU4AAAAAAAAAAAAAAAAEAAYAGBgAAAAAAAAAAAAA/////wAAAAA=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_h3c_netstream_varstringa3281() {
        let data = "AAkAAQAcjYxbTplnAAAAhQAAAAAM0QBYAAAAAAAAAAkAAAAAAAACvgAbnG4AHBBtAAAAEQAAAAAUFBQUFBT//wAAAAAAAAAAAAAAAACJAIkEABEAICAAAAAAAAAAAAAA/////wAAAAD/AAEA";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_h3c_netstream_varstring_tpl3281() {
        let data = "AAkAAQAchZhbTpllAAAADAAAAAAAAAB4DNEAHAACAAgAAQAIABYABAAVAAQACgAEAA4ABAAIAAQADAAEAA8ABAAQAAQAEQAEAAcAAgALAAIAPAABAAYAAQAEAAEABQABAAkAAQANAAEAPQABAFkAAQArAAIAIwABAAAAAQAiAAQAXQAEAFwABADs//8=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_h3c_tpl3281() {
        let data = "AAkAAevuQeBbApBYAAALJwAACwAAAAB0DNEAGwACAAgAAQAIABYABAAVAAQACgAEAA4ABAAIAAQADAAEAA8ABAAQAAQAEQAEAAcAAgALAAIAPAABAAYAAQAEAAEABQABAAkAAQANAAEAPQABAFkAAQArAAIAIwABAAAAAQAiAAQAXQAEAFwABA==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_huawei_netstreama() {
        let data = "AAkAAZ+mjdhabo68AAH7ogAAAAAFIwBACmzbNQpvcMwKbPwpAAAABAAAAMifoYxcn6aJ8AAAAAAACAAfshMKJgAAAAAAAAAAAAAYBgAYGQEAAAAA";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_huawei_netstream_tpl() {
        let data = "AAkAAZ+marBabo6zAAByGgAAAAAAAABsBSMAGQAIAAQADAAEAA8ABAACAAQAAQAEABYABAAVAAQAEgAEAAoAAgAOAAIABwACAAsAAgAQAAIAEQACADoAAgA7AAIA6AACAAYAAQAEAAEABQABAAkAAQANAAEAPQABAFkAAQDSAAM=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_invalid01() {
        let data = "AAkAAgAGHCJV3PXJAAAAAAAAAAAAAAA8BAAADQAIAAQADAAEABUABAAWAAQAAQAEAAIABAAKAAQADgAEAAcAAgALAAIABAABAAYAAQA8AAEAAAA8CAAADQAbABAAHAAQABUABAAWAAQAAQAEAAIABAAKAAQADgAEAAcAAgALAAIABAABAAYAAQA8AAEAAQAWAQAABAAIAAIABAAiAAQAIwABAQAAEAAAAAAAAABkAQAAAAgAAEYgAUS4ERhyAAAAAAAAAAAQIAFEuEAwzZGAdQuu050mIQAA2OAAANjgAAAAYAAAAAEAAAAAAAAAAAB7AHsRAAYAAAAEAAAswKgAAcCoAGkAAVukAAFbpAAAAGIAAAABAAAAAAAAAAAANdkXEQAEAA==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_iptnetflow_reduced_size_encoding_tpa260() {
        let data = "AAkAFUzY50BaiRNdAAVBoQAAAAABAwBAw0DVEArriAoK6AUBAbu2SAAABwAIAAcACAAAAd0ACYHoTNhsCEzYrJwRAAAbIbwk3ZDiuiMJ/AgAAAAAAAAAWAEEABQACAAEAAwABAAPAAQABwACAAsAAgAGAAEACgACAA4AAgD8AAIA/QACAAIABAABAAQAFgAEABUABAAEAAEABQABANEABABQAAYAOAAGAQAAAgEEATglegHiwZfGpsGXwBFr5oy5AgAHAAcABwAHAAAAAwAAAJxM2ImATNispAYA8AAAAAAbIbwk3ZDiuiMJ/AgABY3npsGXx0XBl8ARecpzngIABwAHAAcABwAAAAEAAAAwTNisoEzYrKAGANAAAAAAGyG8JN2Q4rojCfwIAArpgATU4HFKwZfAEdG4AbvTAAgABwAIAAcAAAALAAACSEzYjrhM2KycBgDxAAABABshvCTcAASWl7jNCADBl8AuCuwIBAroBQEAUMldGwB7AAgAewAIAAAABAAAAkFM2KyQTNisoAYA8QAAAAAbIbwk3AAaShYBgQgACuvFBj7dc83Bl8AR4KEEAAIACAAHAAgABwAAAAMAAACYTNioDEzYrJwGAPAAAAAAGyG8JNwABJaXuM0IAAAAAAEDAHi/uDzqwZfJOcGXwBEEERrhAAAHAAcABwAHAAAAAgAAAQZM2JSoTNispBEAABshvCTdkOK6Iwn8CAAK6+MCLiBD9sGXwBGATpFZAAAIAAcACAAHAAAAAwAAAJBM2Ij0TNispBEAABshvCTcAASWl7jNCAAAAAEEAEQK7B8HJZJ9QMGXwBHwHwylAgAIAAcACAAHAAAAAwAAAJhM2ImATNisoAYA8AAAAAAbIbwk3AAElpe4zQgAAAAAAQMAQMNA1REK6ehdCugFAQG7zDcAAAcACAAHAAgAAAADAAAA/UzYrEhM2KycEQAAGyG8JN2Q4rojCfwIAAAAAAEEALwK6ZcINMbWSMGXwBHivAG7HwAIAAcACAAHAAAADwAABxFM2JtQTNisoAYA+QAAAAAbIbwk3AAElpe4zQgACuoWBEDpobzBl8AR7KcUbBgACAAHAAgABwAAAAMAAADqTNisVEzYrKQGAIEAAAAAGyG8JNwABJaXuM0IAArpJAe50RTwwZfAEcjHAFAbAAgABwAIAAcAAAAWAAAGkUzYqxBM2KygBgDxAAAAABshvCTcAASWl7jNCAAAAQYAPC7p7JcK6Y0ECugFAQAAAwMABwAIAAcACAAAAAEAAACBTNisoEzYrKABAAAbIbwk3ZDiuiMJ/AgAAQMAQEBfYAXBl8eAwZfAEQG76j0EAAcABwAHAAcAAAABAAAAKEzYrKRM2KykBgAAGyG8JN2Q4rojCfwIAAAAAAEEAEQK6cgHVCf1r8GXwBHxfEiUAgAIAAcACAAHAAAAAwAAAJhM2IlcTNisnAYA8AAAAAAbIbwk3AAElpe4zQgAAAAAAQMAeArp4Siw0QFnwZfAESs/cgoAAAgABwAIAAcAAAABAAAA60zYrJxM2KycEQAAGyG8JNwABJaXuM0IAAroIlJIBQEBwZfAEc3lhFIAAAgABwAIAAcAAAABAAAAHUzYrKRM2KykEQAAGyG8JNwABJaXuM0IAAAAAQQAgBcrixsK6AgtCugFAQBQ28EaAAcACAAHAAgAAAADAAAHSkzYrGRM2KygBgDwAAAAABshvCTdkOK6Iwn8CAACEYwvCumWFQroBQEBu5UUGQAHAAgABwAIAAAAAwAAALtM2KvgTNisoAYAgQAAAAAbIbwk3ZDiuiMJ/AgAAAA=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_juniper_srx_tplopt() {
        let data = "AAkAA9SXYnZYPMokAAABUgAAAI4AAQAYAQAABAAIAAEAAAAjAAEAIgAEAAABAAAMAgAAAAEAAAAAAABcAQEAFQAIAAQADAAEAAUAAQAEAAEABwACAAsAAgAgAAIACgAEAAkAAQANAAEAEAAEABEABAASAAQABgABAA4ABAAPAAQAAQAEAAIABAAWAAQAFQAEADwAAQ==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_macaddra() {
        let data = "AAkAAQAAhrhWGNCFAAAAAgAAAGEBAQLcBv4irBAgAQAWrBAgyQBQVsAAAQAMKXCGCREAe6wQIMkAe6wQIGQADClwhgkADCmNr8MRAHusECBkAHusECDJAAwpja/DAAwpcIYJBucVrBAgAQBQrBAgyQBQVsAAAQAMKXCGCQYAUKwQIMnnFawQIAEADClwhgkAUFbAAAEG5xasECABAbusECDJAFBWwAABAAwpcIYJBgG7rBAgyecWrBAgAQAMKXCGCQBQVsAAAQbnF6wQIAEAi6wQIMkAUFbAAAEADClwhgkGAIusECDJ5xesECABAAwpcIYJAFBWwAABBucYrBAgAQAXrBAgyQBQVsAAAQAMKXCGCQYAF6wQIMnnGKwQIAEADClwhgkAUFbAAAEG5xmsECABA+OsECDJAFBWwAABAAwpcIYJBgPjrBAgyecZrBAgAQAMKXCGCQBQVsAAAQbnGqwQIAEBu6wQIMkAUFbAAAEADClwhgkGAbusECDJ5xqsECABAAwpcIYJAFBWwAABBucbrBAgAQCHrBAgyQBQVsAAAQAMKXCGCQYAh6wQIMnnG6wQIAEADClwhgkAUFbAAAEG5xysECABAG6sECDJAFBWwAABAAwpcIYJBgBurBAgyeccrBAgAQAMKXCGCQBQVsAAAQbnHawQIAEAb6wQIMkAUFbAAAEADClwhgkGAG+sECDJ5x2sECABAAwpcIYJAFBWwAABBucerBAgAQCPrBAgyQBQVsAAAQAMKXCGCQYAj6wQIMnnHqwQIAEADClwhgkAUFbAAAEG5x+sECABDT2sECDJAFBWwAABAAwpcIYJBg09rBAgyecfrBAgAQAMKXCGCQBQVsAAAQbnIKwQIAEAUKwQIMkAUFbAAAEADClwhgkGAFCsECDJ5yCsECABAAwpcIYJAFBWwAABBuchrBAgAQAZrBAgyQBQVsAAAQAMKXCGCQYAGawQIMnnIawQIAEADClwhgkAUFbAAAEAAAA=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_macaddr_tpl() {
        let data = "AAkAAwAAdUhWGNCAAAAAAAAAAGEAAABEAQEABwAEAAEABwACAAgABAALAAIADAAEADgABgBQAAYBAgAHAAQAAQAHAAIACwACABsAEAAcABAAOAAGAFAABgABABgBAwAEAAgAAQAEACoABAApAAQAAAEDABAAAAAAAAAAAQAAAAA=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_nprobea() {
        let data = "AAkAAQAAhMZWFr61AAAAAQAAAJMBAQA4AAAAyAAAAAIGEBgAFqwQIMkAAAD+IqwQIAEAAAAAAAAAAAAAAAAAAAAAAAAFAAAAAA0AAQ==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_nprobe_dpi() {
        let data = "AAkAAgABY3gAAAH2AAAAAgAAAAAAAAA8AQAADQAWAAQAFQAEAAQAAQAIAAQADAAEAAcAAgALAAIAAQAEAAIABABfAAQAYAAg4PYAAuD3ABABAABoAAGKiAABlkAAAAAAAAAAAAAAAAAAAAAAUgAAAAEAAABSAAAAAAAiAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUgDBAAABrBAAZORP7///+gdsAAAAEQAAAAAAAAAAAAAAAA==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_nprobe_tpl() {
        let data = "AAkAAwAAhMZWFr61AAAAAAAAAJMAAACcAQEAEgABAAQAAgAEAAQAAQAFAAEABgABAAcAAgAIAAQACQABAAoAAgALAAIADAAEAA0AAQAOAAIADwAEABAABAARAAQAFQAEABYABAECABIAAQAEAAIABAAEAAEABQABAAYAAQAHAAIACgACAAsAAgAOAAIAEAAEABEABAAVAAQAFgAEABsAEAAcABAAHQABAB4AAQA+ABAAAQAYAQMABAAIAAEABAAqAAQAKQAEAAABAwAQAAAAAAAAAAEAAAAA";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_paloalto_81a257_1flowset_in_large_zerofilled_packet() {
        let data = "AAkAAT9TEgBbF9+ROd2xIwEAAAABAQCgAAAAAAAAAWsAAAADBgBeAFiG3AIGHc2MKMQ6htwBnB3NjBI/UtdoP1LXaAAAAAAAAAAAFcukAgAAY3VrZXJiZXJvcwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHVua25vd24AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_paloalto_81_tpl256_263() {
        let data = "AAkACD9TEgBbF9+ROd2xIAEAAAAAAAK0AQAAEQABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAIAAQACgAEAAsAAgAMAAQADgAEABUABAAWAAQAIAACAD0AAQCUAAgA6QABAQEAFAABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAIAAQACgAEAAsAAgAMAAQADgAEABUABAAWAAQAIAACAD0AAQCUAAgA6QABAVoABN19ACDdfgBAAQQAFQABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAIAAQACgAEAAsAAgAMAAQADgAEABUABAAWAAQAIAACAD0AAQCUAAgA6QABAOEABADiAAQA4wACAOQAAgEFABgAAQAIAAIABAAEAAEABQABAAYAAQAHAAIACAAEAAoABAALAAIADAAEAA4ABAAVAAQAFgAEACAAAgA9AAEAlAAIAOkAAQDhAAQA4gAEAOMAAgDkAAIBWgAE3X0AIN1+AEABAgARAAEACAACAAQABAABAAUAAQAGAAEABwACABsAEAAKAAQACwACABwAEAAOAAQAFQAEABYABAAgAAIAPQABAJQACADpAAEBAwAUAAEACAACAAQABAABAAUAAQAGAAEABwACABsAEAAKAAQACwACABwAEAAOAAQAFQAEABYABAAgAAIAPQABAJQACADpAAEBWgAE3X0AIN1+AEABBgAVAAEACAACAAQABAABAAUAAQAGAAEABwACABsAEAAKAAQACwACABwAEAAOAAQAFQAEABYABAAgAAIAPQABAJQACADpAAEBGQAQARoAEADjAAIA5AACAQcAGAABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAbABAACgAEAAsAAgAcABAADgAEABUABAAWAAQAIAACAD0AAQCUAAgA6QABARkAEAEaABAA4wACAOQAAgFaAATdfQAg3X4AQA==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_paloalto_panosa() {
        let data = "AAkACGt7OuBaCa6jDFyPcwAAAAEBAQCfAAAAAAAAAEYAAAABBgASAFAXI6sbAAAAF8FvCiBbzQAAABhrezrga3s64AAAAAAAAAAABm7kAQAAY3VpbmNvbXBsZXRlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQCfAAAAAAAAAG8AAAABBgAamxYKIGlnAAAAGAG7onMYHgAAABdrezrga3YOqAAAAAAAAAAABlZzBQAAY3Vzc2wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQCfAAAAAAAAAEYAAAABBgACy2UKIJCRAAAAGAG7IsqtfgAAABdrezrga3s64AAAAAAAAAACFDUgAQAAY3VpbmNvbXBsZXRlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQCfAAAAAAAAAEYAAAABBgASAbsX0TRjAAAAF8EpCoKRLAAAABhrezrga3s64AAAAAAAAAACD58DAQAAY3VpbmNvbXBsZXRlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQCfAAAAAAAAAE4AAAABBgAC2LkKMmE5AAAAFxU4CjJgFAAAABhrezrga3s64AAAAAAAAAACB/+uAQAAY3VpbmNvbXBsZXRlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQCfAAAAAAAAAE4AAAABBgASFTgKMmAUAAAAGNi5CjJhOQAAABdrezrga3s64AAAAAAAAAACB/+uAQAAY3VpbmNvbXBsZXRlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQCfAAAAAAAAAEYAAAABBgASAbsi6q2TAAAAF+qkCjDQ0QAAABhrezrga3s64AAAAAAAAAAABEmMAQAAY3VpbmNvbXBsZXRlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQCfAAAAAAAAAEYAAAABBgAC8vQKgqcrAAAAGAG7QTRs/gAAABdrezrga3s64AAAAAAAAAACFp3LAQAAY3VpbmNvbXBsZXRlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_paloalto_panos_tpl() {
        let data = "AAkACGt7OuBaCa6jDFyPbQAAAAEAAABMAQAAEQABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAIAAQACgAEAAsAAgAMAAQADgAEABUABAAWAAQAIAACAD0AAQCUAAgA6QABAAAAXAEEABUAAQAIAAIABAAEAAEABQABAAYAAQAHAAIACAAEAAoABAALAAIADAAEAA4ABAAVAAQAFgAEACAAAgA9AAEAlAAIAOkAAQDhAAQA4gAEAOMAAgDkAAIAAABMAQIAEQABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAbABAACgAEAAsAAgAcABAADgAEABUABAAWAAQAIAACAD0AAQCUAAgA6QABAAAAXAEGABUAAQAIAAIABAAEAAEABQABAAYAAQAHAAIAGwAQAAoABAALAAIAHAAQAA4ABAAVAAQAFgAEACAAAgA9AAEAlAAIAOkAAQEZABABGgAQAOMAAgDkAAIAAABYAQEAFAABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAIAAQACgAEAAsAAgAMAAQADgAEABUABAAWAAQAIAACAD0AAQCUAAgA6QABAVoABN19ACDdfgBAAAAAaAEFABgAAQAIAAIABAAEAAEABQABAAYAAQAHAAIACAAEAAoABAALAAIADAAEAA4ABAAVAAQAFgAEACAAAgA9AAEAlAAIAOkAAQDhAAQA4gAEAOMAAgDkAAIBWgAE3X0AIN1+AEAAAABYAQMAFAABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAbABAACgAEAAsAAgAcABAADgAEABUABAAWAAQAIAACAD0AAQCUAAgA6QABAVoABN19ACDdfgBAAAAAaAEHABgAAQAIAAIABAAEAAEABQABAAYAAQAHAAIAGwAQAAoABAALAAIAHAAQAA4ABAAVAAQAFgAEACAAAgA9AAEAlAAIAOkAAQEZABABGgAQAOMAAgDkAAIBWgAE3X0AIN1+AEA=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_softflowd_tpla() {
        let data = "AAkACQAAsBRWFr4+AAAAAQAAAAAAAABABAAADgAIAAQADAAEABUABAAWAAQAAQAEAAIABAAKAAQADgAEAAcAAgALAAIABAABAAYAAQA8AAEABQABAAAAQAgAAA4AGwAQABwAEAAVAAQAFgAEAAEABAACAAQACgAEAA4ABAAHAAIACwACAAQAAQAGAAEAPAABAAUAAQQAAPSsECBkrBAg+AAABMEAAATAAAAATAAAAAEAAAAAAAAAAAB7AHsRAAQArBAg+KwQIGQAAATBAAAEwAAAAEwAAAABAAAAAAAAAAAAewB7EQAEAKwQIGSsECDJAAAa6gAAGukAAABMAAAAAQAAAAAAAAAAAHsAexEABACsECDJrBAgZAAAGuoAABrpAAAATAAAAAEAAAAAAAAAAAB7AHsRAAQArBAgZKwQIMoAACsaAAArGgAAAEwAAAABAAAAAAAAAAAAewB7EQAEAKwQIMqsECBkAAArGgAAKxoAAABMAAAAAQAAAAAAAAAAAHsAexEABAAIAABE/oAAAAAAAAACDCn//oM7bv8CAAAAAAAAAAAAAAAAAAEAAKAQAAALTwAAAqAAAAAHAAAAAAAAAAAAAIYAOgAGAA==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_streamcore_tpla256() {
        let data = "AAkAAmaYVl9Ydht/f7xq8gAAAAAAAALMAQAAFwABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAIAAQACgAEAAsAAgAMAAQADgAEABUABAAWAAQgBAABIAAABCABAAQgAgAEIAMAAiDAAAQgwQAEIMIABCDDAAQgxAAEAQEAHAABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAIAAQACgAEAAsAAgAMAAQADgAEABUABAAWAAQgBAABIAAABCABAAQgAgAEIAMAAiDAAAQgwQAEIMIABCDDAAQgxAAEIMUABCDGAAQgxwAEIMgABCDJAAQBAgAcAAEACAACAAQABAABAAUAAQAGAAEABwACAAgABAAKAAQACwACAAwABAAOAAQAFQAEABYABCAEAAEggAACIIEAAiCCAAIggwACIIQAAiCFAAEghgABIIcAASCIAAEgwAAEIMEABCDCAAQgwwAEIMQABAEDACEAAQAIAAIABAAEAAEABQABAAYAAQAHAAIACAAEAAoABAALAAIADAAEAA4ABAAVAAQAFgAEIAQAASCAAAIggQACIIIAAiCDAAIghAACIIUAASCGAAEghwABIIgAASDAAAQgwQAEIMIABCDDAAQgxAAEIMUABCDGAAQgxwAEIMgABCDJAAQBBAAeAAEACAACAAQABAABAAUAAQAGAAEABwACAAgABAAKAAQACwACAAwABAAOAAQAFQAEABYABCAEAAEgAAAEIAEABCACAAQgAwACIEAAKCBBAJYgwAAEIMEABCDCAAQgwwAEIMQABCDFAAQgxgAEIMcABCDIAAQgyQAEAQUAHgABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAIAAQACgAEAAsAAgAMAAQADgAEABUABAAWAAQgBAABIAAABCABAAQgAgAEIAMAAiBCAB4gQwAeIMAABCDBAAQgwgAEIMMABCDEAAQgxQAEIMYABCDHAAQgyAAEIMkABAEAAKAAAAAAAAAAgAAAAAMGKBMfkGROKMkAAASAw5kK54CWAAAEfGaXojZml4q6AQAAAAAAAAAAAAAAAAAAAAAEkwAABJsAAASoAAAFmwAAAAAAAAAAAAAArAAAAAQGKBPDmQrngJYAAAR8H5BkTijJAAAEgGaXoj1ml4q5AAAAAAAAAAAAAAAAAAAAAAAEkwAABJsAAASoAAAFmwAAAAA=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_streamcore_tpla260() {
        let data = "AAkAAmaB/8NYdhXHf7SlJAAAAAAAAALMAQAAFwABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAIAAQACgAEAAsAAgAMAAQADgAEABUABAAWAAQgBAABIAAABCABAAQgAgAEIAMAAiDAAAQgwQAEIMIABCDDAAQgxAAEAQEAHAABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAIAAQACgAEAAsAAgAMAAQADgAEABUABAAWAAQgBAABIAAABCABAAQgAgAEIAMAAiDAAAQgwQAEIMIABCDDAAQgxAAEIMUABCDGAAQgxwAEIMgABCDJAAQBAgAcAAEACAACAAQABAABAAUAAQAGAAEABwACAAgABAAKAAQACwACAAwABAAOAAQAFQAEABYABCAEAAEggAACIIEAAiCCAAIggwACIIQAAiCFAAEghgABIIcAASCIAAEgwAAEIMEABCDCAAQgwwAEIMQABAEDACEAAQAIAAIABAAEAAEABQABAAYAAQAHAAIACAAEAAoABAALAAIADAAEAA4ABAAVAAQAFgAEIAQAASCAAAIggQACIIIAAiCDAAIghAACIIUAASCGAAEghwABIIgAASDAAAQgwQAEIMIABCDDAAQgxAAEIMUABCDGAAQgxwAEIMgABCDJAAQBBAAeAAEACAACAAQABAABAAUAAQAGAAEABwACAAgABAAKAAQACwACAAwABAAOAAQAFQAEABYABCAEAAEgAAAEIAEABCACAAQgAwACIEAAKCBBAJYgwAAEIMEABCDCAAQgwwAEIMQABCDFAAQgxgAEIMcABCDIAAQgyQAEAQUAHgABAAgAAgAEAAQAAQAFAAEABgABAAcAAgAIAAQACgAEAAsAAgAMAAQADgAEABUABAAWAAQgBAABIAAABCABAAQgAgAEIAMAAiBCAB4gQwAeIMAABCDBAAQgwgAEIMMABCDEAAQgxQAEIMYABCDHAAQgyAAEIMkABAEEAkQAAAAAAAAPZwAAAAoGKBofkGROKMkAAASA0OsKGwgUAAAEfGaBwQNmgPnOAQAAAAAAAAARAAAAEwAAbGl2ZS5sZW1kZS5mcgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC9tdXguanNvbgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABJMAAASbAAAEqAAABZsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAL7AAAAAsGKBrQ6wobCBQAAAR8H5BkTijJAAAEgGaBwRVmgPnOAAAAAAAAAAARAAAAEwAAbGl2ZS5sZW1kZS5mcgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC9tdXguanNvbgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABJMAAASbAAAEqAAABZsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_ubnt_edgeroutera1024() {
        let data = "AAkACBhmVoJX1DOCAAB8UgAAAAAEAAHcGGDH8xhgx/MAAACuAAAAAgQABAAAAAAAAAAKAQCHCgQA+wA1Q1AAABEGvu++709E2ee+74kAAAAAAAQYYMfzGGDH8wAAAFcAAAABBAAEAAAAAAAAAAoBAIgKBAD7ADVDUAAAEQa+777vT0TZ577viQAAAAAABBgugR0YLF1aAAAHgAAAAA8EAAQAAAAAAAAACgEA6AoEAPsBu8ipABsGBr7vvu9PRNnnvu+JAAAAAAAEGC6BHRgsXVoAAAJiAAAACAQABAAAAAAAAAAKAQDoCgQA+wG7yKoAGwYGvu++709E2ee+74kAAAAAAAQYY6ItGGDuXwAACXQAAAAVBAAEAAAAAAAAAAoFAFsKBAD7Abur5gAfBga+777vT0TZ577viQAAAAAABBhjocwYYO7FAAAn3AAAAB4EAAQAAAAAAAAACgEAHgoEAPsBu4ICAB8GBr7vvu9PRNnnvu+JAAAAAAAEGC6V4RguleEAAADYAAAABAQABAAAAAAAAAAKAwBkCgQA+wG7/IIAGwYGvu++709E2ee+74kAAAAAAAQYYO5fGGDuXwAAAJgAAAABBAAEAAAAAAAAAAoBAIcKBAD7ADUlGQAAEQa+777vT0TZ577viQAAAAAABA==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_ubnt_edgeroutera1025() {
        let data = "AAkACBhm66lX1DOoAAB7sAAAAAAEAQHcGC+LsBgvizwAAAEEAAAABQQAAgAEAQAAAADAqAFiCgAASddBAbsAGwZE2ee+7yJE2ee+744AAAAAAAQYYeg8GGHoPAAAACAAAAABBAAAAAQBAAAAAAoEAPv/////pgonEQAAEQAAAAAAAAAAAAAAAAAAAAAABBhh6DwYYeg8AAAAhwAAAAEEAAAABAEAAAAACgQA+/////+dZ5PsAAARAAAAAAAAAAAAAAAAAAAAAAAEGGHoPBhh6DwAAACHAAAAAQQAAAAEAQAAAAAKBAD7/////4zn3k8AABEAAAAAAAAAAAAAAAAAAAAAAAQYYeg8GGHoPAAAAIcAAAABBAAAAAQBAAAAAAoEAPv/////wqXcBwAAEQAAAAAAAAAAAAAAAAAAAAAABBhh6DwYYeg8AAAAhwAAAAEEAAAABAEAAAAACgQA+/////+I89uvAAARAAAAAAAAAAAAAAAAAAAAAAAEGGHoPBhh6DwAAACHAAAAAQQAAAAEAQAAAAAKBAD7/////5VXm5gAABEAAAAAAAAAAAAAAAAAAAAAAAQYL6DUGByKKAAADlQAAAAVBAACAAQBAAAAAMCoAWYKAgBfukoBuwAbBga+777vuUTZ577vjgAAAAAABA==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_ubnt_edgerouter_tpl() {
        let data = "AAkABBhm66lX1DOoAAB7rwAAAAAAAABYBAAAFAAVAAQAFgAEAAEABAACAAQAPAABAAoAAgAOAAIAPQABAAMABAAIAAQADAAEAAcAAgALAAIABQABAAYAAQAEAAEAOAAGAFAABgA6AAIAyQAEAAAAWAQBABQAFQAEABYABAABAAQAAgAEADwAAQAKAAIADgACAD0AAQADAAQACAAEAAwABAAHAAIACwACAAUAAQAGAAEABAABAFEABgA5AAYAOwACAMkABAAAAFgIAAAUABUABAAWAAQAAQAEAAIABAA8AAEACgACAA4AAgA9AAEAAwAEABsAEAAcABAABQABAAcAAgALAAIABgABAAQAAQA4AAYAUAAGADoAAgDJAAQAAABYCAEAFAAVAAQAFgAEAAEABAACAAQAPAABAAoAAgAOAAIAPQABAAMABAAbABAAHAAQAAUAAQAHAAIACwACAAYAAQAEAAEAUQAGADkABgA7AAIAyQAE";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_unknown_tpl266_292a() {
        let data = "AAkABgAJCF9aIYunAACJEAAAAAAAAQAaAQAABAAMAAEABAApAAQAKgAEACgABAABABoBAQAEAAwAAQAEADAAAQAxAAEAMgAEAAAARAEKAA8ACAAEAAwABAAEAAEABwACAAsAAgAFAAEACgAEAD0AAQCWAAQAlwAEAAEACAACAAgA6gAEAOsABAAwAAEAAABEASQADwAIAAQADAAEAAQAAQAHAAIACwACAAUAAQAOAAQAPQABAJYABACXAAQAAQAIAAIACADqAAQA6wAEADAAAQEKADjAqAADwKgAAhEAiQCJAAAAAA0AWiGLmlohi5oAAAAAAAAATgAAAAAAAAABAAAAAAAAAAABASQAOMCoAATAqAAFEeMSGMcAAAAADQFaIYudWiGLnQAAAAAAAADoAAAAAAAAAAEAAAAAAAAAAAE=";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
    #[test]
    fn test_data_decoder_netflow9_test_valid01() {
        let data = "AAkACQAAsBRWFr4+AAAAAQAAAAAAAABABAAADgAIAAQADAAEABUABAAWAAQAAQAEAAIABAAKAAQADgAEAAcAAgALAAIABAABAAYAAQA8AAEABQABAAAAQAgAAA4AGwAQABwAEAAVAAQAFgAEAAEABAACAAQACgAEAA4ABAAHAAIACwACAAQAAQAGAAEAPAABAAUAAQQAAPSsECBkrBAg+AAABMEAAATAAAAATAAAAAEAAAAAAAAAAAB7AHsRAAQArBAg+KwQIGQAAATBAAAEwAAAAEwAAAABAAAAAAAAAAAAewB7EQAEAKwQIGSsECDJAAAa6gAAGukAAABMAAAAAQAAAAAAAAAAAHsAexEABACsECDJrBAgZAAAGuoAABrpAAAATAAAAAEAAAAAAAAAAAB7AHsRAAQArBAgZKwQIMoAACsaAAArGgAAAEwAAAABAAAAAAAAAAAAewB7EQAEAKwQIMqsECBkAAArGgAAKxoAAABMAAAAAQAAAAAAAAAAAHsAexEABAAIAABE/oAAAAAAAAACDCn//oM7bv8CAAAAAAAAAAAAAAAAAAEAAKAQAAALTwAAAqAAAAAHAAAAAAAAAAAAAIYAOgAGAA==";
        let res = test_data_decoder(data);
        assert_eq!(res.is_some(), true)
    }
}
