use std::fmt::Display;

use bytes::{Bytes, BytesMut};
use memchr::memchr;
use snap::raw::{Decoder as Comp};
use tokio_util::codec::Decoder;
use tracing::{trace, warn};
use vector_config::configurable_component;

use super::{BoxedFramingError, FramingError};
use crate::StreamDecodingError;

#[derive(Debug)]
pub enum StrataSnappyDecoderError {
    DecompressionFailed {
        err: snap::Error,
    },

    DecompressionBufferSizeExceeded {
        actual_size: usize,
        max_size: usize,
    },

    NoHeaderDelimiter,

    DataAfterEoF,
}

impl Display for StrataSnappyDecoderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StrataSnappyDecoderError::DecompressionFailed { err } => {
                write!(f, "Strata Snappy decompression failed: {}", err)
            }
            StrataSnappyDecoderError::DecompressionBufferSizeExceeded {
                actual_size,
                max_size,
                ..
            } => write!(
                f,
                "Decompressed Strata Snappy frame size {} exceeds maximum allowed size of {} bytes",
                actual_size, max_size
            ),
            StrataSnappyDecoderError::NoHeaderDelimiter => {
                write!(f, "No header delimiter (newline) found in Strata log data")
            },
            StrataSnappyDecoderError::DataAfterEoF => {
                write!(f, "Data received after end of Strata log stream")
            }
        }
    }
}

impl std::error::Error for StrataSnappyDecoderError {}

impl FramingError for StrataSnappyDecoderError {
    fn as_any(&self) -> &dyn std::any::Any {
        self as &dyn std::any::Any
    }
}

impl StreamDecodingError for StrataSnappyDecoderError {
    fn can_continue(&self) -> bool {
        false
    }
}

/// Configuration for the Strata Snappy decoder.
#[configurable_component]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StrataSnappyDecoderConfig {
    /// Options for the Strata Snappy decoder.
    #[serde(default, skip_serializing_if = "vector_core::serde::is_default")]
    pub strata_snappy: StrataSnappyDecoderOptions,
}

/// Default max frame size
fn default_max_frame_bytes() -> usize {
    16 * 1024 * 1024
}

/// Configuration options for the Strata Snappy decoder.
#[configurable_component]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StrataSnappyDecoderOptions {
    /// Maximum allowed size for decompressed frames in bytes.
    /// The frame must have atleast one complete event, stream is
    /// either abandoned or event is skipped depending on the
    /// skip-on-error config if at-least one event doesn't fit in this frame.
    #[serde(
        default = "default_max_frame_bytes",
        skip_serializing_if = "vector_core::serde::is_default"
    )]
    pub max_frame_bytes: usize,
}

impl Default for StrataSnappyDecoderOptions {
    fn default() -> Self {
        Self {
            max_frame_bytes: default_max_frame_bytes(),
        }
    }
}

impl StrataSnappyDecoderConfig {
    /// Creates a new `StrataSnappyDecoderConfig` with default options.
    pub fn new() -> Self {
        Default::default()
    }

    /// Creates a new `StrataSnappyDecoderConfig` with a specified maximum decompressed size.
    pub const fn new_with_max_size(max_decompressed_size: usize) -> Self {
        Self {
            strata_snappy: StrataSnappyDecoderOptions {
                max_frame_bytes: max_decompressed_size,
            },
        }
    }

    /// Builds a `StrataSnappyDecoder` from the configuration.
    pub fn build(&self) -> StrataSnappyDecoder {
        StrataSnappyDecoder::new(self.strata_snappy.clone())
    }
}

/// Strata log format where each file consists of:
/// 1. A header line (terminated by newline character, ASCII 10)
/// 2. A single Snappy-compressed block containing the actual log data (not chunked snappy)
///
/// The decoder preserves the header metadata and decompresses the payload, returning
/// the header as the first line followed by the decompressed log entries enriched with header metadata
#[derive(Debug, Clone)]
pub struct StrataSnappyDecoder {
    cfg: StrataSnappyDecoderOptions,
    finished: bool,
}

impl StrataSnappyDecoder {
    /// Creates a new `StrataSnappyDecoder` with the specified options.
    pub fn new(cfg: StrataSnappyDecoderOptions) -> Self {
        Self { cfg, finished: false }
    }
}

impl Default for StrataSnappyDecoder {
    fn default() -> Self {
        Self::new(StrataSnappyDecoderOptions::default())
    }
}

impl Decoder for StrataSnappyDecoder {
    type Item = Bytes;
    type Error = BoxedFramingError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        trace!("Decode called with {} bytes", src.len());
        if src.len() > self.cfg.max_frame_bytes {
            Err(Box::new(
                StrataSnappyDecoderError::DecompressionBufferSizeExceeded {
                    actual_size: src.len(),
                    max_size: self.cfg.max_frame_bytes,
            }))
        } else {
            Ok(None)
        }
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        trace!("Decode EOF called with {} bytes (finished = {})", src.len(), self.finished);
        let src = src.split();
        match (self.finished, memchr(b'\n', &src)) {
            (false, Some(hdr_offset)) => {
                let hdr_offset = hdr_offset + 1;
                let compressed_data = &src[hdr_offset..];
                if compressed_data.is_empty() {
                    trace!(message = "No compressed Strata log payload available at EOF.");
                    return Ok(None);
                }
                let data_len = snap::raw::decompress_len(compressed_data)
                    .map_err(|err| {
                        warn!( "Failed to get decompressed length, {err:?}");
                        StrataSnappyDecoderError::DecompressionFailed { err }
                    })?;
                trace!(
                    message = "Reserving bytes for decompression buffer.",
                    reserving = data_len,
                    max_allowed = self.cfg.max_frame_bytes);
                if data_len > self.cfg.max_frame_bytes {
                    warn!(
                        "Decompressed size {} exceeds maximum allowed size of {} bytes",
                        data_len, self.cfg.max_frame_bytes
                    );
                    return Err(Box::new(
                            StrataSnappyDecoderError::DecompressionBufferSizeExceeded {
                                actual_size: data_len,
                                max_size: self.cfg.max_frame_bytes,
                            }));
                }
                let mut out = BytesMut::new();
                out.extend_from_slice(&src[..hdr_offset]);
                out.resize(hdr_offset + data_len, 0);
                let wrote = Comp::new().decompress(&src[hdr_offset..], &mut out[hdr_offset..])
                    .map_err(|err| {
                        warn!( "Decompression failed, {err:?}");
                        StrataSnappyDecoderError::DecompressionFailed { err }
                    })?;
                if wrote != data_len {
                    warn!(
                        "Decompressed size mismatch: expected {}, got {}",
                        data_len, wrote
                    );
                    out.resize(hdr_offset + wrote, 0);
                }
                self.finished = true;
                Ok(Some(out.freeze()))
            }
            (false, None) => {
                return Err(Box::new(StrataSnappyDecoderError::NoHeaderDelimiter));
            }
            (true, _) if src.is_empty() => Ok(None),
            _ => Err(Box::new(StrataSnappyDecoderError::DataAfterEoF)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cmp;
    use bytes::BufMut;
    use rand::SeedableRng;
    use rstest::rstest;
    use tracing_test::traced_test;
    use rand::{RngCore, rngs::StdRng};
    use itertools::Itertools;
    use super::*;

    #[test]
    fn decode_strata_log_simple() {
        let header = b"metadata:timestamp=123456789";
        let payload = b"Hello, World!";

        // Compress the payload
        let compressed = snap::raw::Encoder::new()
            .compress_vec(payload)
            .expect("compression failed");

        // Combine header and compressed payload
        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed);

        let mut decoder = StrataSnappyDecoder::new(StrataSnappyDecoderOptions::default());
        assert_eq!(decoder.decode(&mut input).unwrap(), None);

        let expected = format!("{}\n{}",
            std::str::from_utf8(header).unwrap(),
            std::str::from_utf8(payload).unwrap()
        );
        assert_eq!(decoder.decode_eof(&mut input).unwrap(), Some(expected.into()));
    }

    #[test]
    fn decode_strata_log_json() {
        let header = br#"{"bucket":"test","timestamp":"2024-01-01T00:00:00Z"}"#;
        let json_payload = br#"{"level":"info","message":"Test log entry","timestamp":"2024-01-01T00:00:00Z"}"#;

        // Compress the JSON payload
        let compressed = snap::raw::Encoder::new()
            .compress_vec(json_payload)
            .expect("compression failed");

        // Combine header and compressed payload
        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed);

        let mut decoder = StrataSnappyDecoder::new(StrataSnappyDecoderOptions::default());

        let result = decoder.decode_eof(&mut input).unwrap();
        assert!(result.is_some());

        let output = result.unwrap();

        // Output should start with header
        let output_str = std::str::from_utf8(&output).expect("should be valid UTF-8");
        let lines: Vec<&str> = output_str.lines().collect();

        assert_eq!(lines.len(), 2);

        // First line should be header
        let header_parsed: serde_json::Value = serde_json::from_str(lines[0])
            .expect("header should be valid JSON");
        assert_eq!(header_parsed["bucket"], "test");

        // Second line should be the log entry
        let log_parsed: serde_json::Value = serde_json::from_str(lines[1])
            .expect("log should be valid JSON");
        assert_eq!(log_parsed["level"], "info");
        assert_eq!(log_parsed["message"], "Test log entry");
    }

    #[test]
    fn decode_empty_after_header() {
        let header = b"metadata";
        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');

        let mut decoder = StrataSnappyDecoder::new(StrataSnappyDecoderOptions::default());

        let result = decoder.decode_eof(&mut input).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn decode_no_header_newline() {
        let input_data = b"no newline here just compressed data";
        let mut input = BytesMut::from(&input_data[..]);

        let mut decoder = StrataSnappyDecoder::new(StrataSnappyDecoderOptions::default());

        let result = decoder.decode_eof(&mut input);
        assert!(result.is_err());
    }

    #[test]
    fn decode_with_max_size_limit() {
        let header = b"metadata";
        let mut rng = rand::thread_rng();
        let large_payload = gen_random_str_len(100, &mut rng);

        let compressed = snap::raw::Encoder::new()
            .compress_vec(large_payload.as_bytes())
            .expect("compression failed");

        let mut input0 = BytesMut::new();
        input0.extend_from_slice(header);
        input0.put_u8(b'\n');
        input0.extend_from_slice(&compressed);

        let mut decoder = StrataSnappyDecoder::new(
            StrataSnappyDecoderOptions{
                max_frame_bytes: cmp::min(compressed.len(), large_payload.len()) - 1,
            });

        let mut input1 = input0.clone();

        let result = decoder.decode(&mut input0);
        assert!(result.is_err());
        let result = decoder.decode_eof(&mut input0);
        assert!(result.is_err());

        let mut decoder = StrataSnappyDecoder::new(
            StrataSnappyDecoderOptions{
                max_frame_bytes: 99,
            });
        let result = decoder.decode_eof(&mut input1);
        assert!(result.is_err());
    }

    #[test]
    fn decode_with_max_size_within_limit() {
        let header = b"metadata";
        let payload = b"Small payload";

        let compressed = snap::raw::Encoder::new()
            .compress_vec(payload)
            .expect("compression failed");

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed);

        // Set max size to 1000 (more than payload size)
        let mut decoder = StrataSnappyDecoder::new(
            StrataSnappyDecoderOptions{
                max_frame_bytes: 5000,
            });

        let result = decoder.decode_eof(&mut input).unwrap();
        assert!(result.is_some());

        let output = result.unwrap();
        let output_str = std::str::from_utf8(&output).expect("should be valid UTF-8");
        assert!(output_str.contains("metadata"));
        assert!(output_str.contains("Small payload"));
    }

    #[test]
    fn decode_invalid_snappy_data() {
        let header = b"metadata";
        let invalid_compressed = b"this is not valid snappy data";

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(invalid_compressed);

        let mut decoder = StrataSnappyDecoder::new(StrataSnappyDecoderOptions::default());

        let result = decoder.decode_eof(&mut input);
        assert!(result.is_err());
    }

    #[test]
    fn decode_multiple_records_sequentially() {
        // First record
        let header1 = b"hdr0";
        let payload1 = b"First record data\nSecond record data";
        let compressed1 = snap::raw::Encoder::new()
            .compress_vec(payload1)
            .expect("compression failed");

        let mut input1 = BytesMut::new();
        input1.extend_from_slice(header1);
        input1.put_u8(b'\n');
        input1.extend_from_slice(&compressed1);

        let mut decoder = StrataSnappyDecoder::new(StrataSnappyDecoderOptions::default());

        let result1 = decoder.decode_eof(&mut input1).unwrap();
        let output1 = result1.unwrap();
        let output1: Vec<&str> = std::str::from_utf8(&output1).unwrap().split('\n').collect();
        assert_eq!(output1, vec!["hdr0", "First record data", "Second record data"]);

        assert_eq!(decoder.decode_eof(&mut input1).unwrap(), None);
        assert_eq!(decoder.decode_eof(&mut input1).unwrap(), None);

        // fails if data is fed again
        input1.extend_from_slice(b"extra data");
        if let Err(e) = decoder.decode_eof(&mut input1) {
            assert!(e.to_string().contains("Data received after end of"));
        }
    }

    #[test]
    fn decode_invalid_snappy_data_with_skip_on_error_false() {
        let header = b"metadata";
        let invalid_compressed = b"this is not valid snappy data";

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(invalid_compressed);

        // skip_on_error = false - errors should propagate
        let mut decoder = StrataSnappyDecoder::new(
            StrataSnappyDecoderOptions{
                max_frame_bytes: default_max_frame_bytes(),
            });

        let result = decoder.decode_eof(&mut input);
        assert!(result.is_err(), "Expected error when skip_on_error=false");

        // Verify the error indicates it cannot continue
        let err = result.unwrap_err();
        assert!(
            !err.can_continue(),
            "Error should not be continuable when skip_on_error=false"
        );
    }

    #[test]
    fn decode_with_max_size_limit_skip_on_error_false() {
        let header = b"metadata";
        let large_payload = vec![b'A'; 10000];

        let compressed = snap::raw::Encoder::new()
            .compress_vec(&large_payload)
            .expect("compression failed");

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed);

        // Set max size to 5000 (less than payload size) with skip_on_error = false
        let mut decoder = StrataSnappyDecoder::new(
            StrataSnappyDecoderOptions{
                max_frame_bytes: 5000,
            });

        let result = decoder.decode_eof(&mut input);
        assert!(result.is_err(), "Expected error when buffer size exceeded");

        // Verify the error indicates it cannot continue
        let err = result.unwrap_err();
        assert!(
            !err.can_continue(),
            "Error should not be continuable when skip_on_error=false"
        );
    }

    #[test]
    fn decode_no_header_newline_skip_on_error_false() {
        let input_data = b"no newline here just compressed data";
        let mut input = BytesMut::from(&input_data[..]);

        // skip_on_error = false - errors should propagate
        let mut decoder = StrataSnappyDecoder::new(
            StrataSnappyDecoderOptions{
                max_frame_bytes: default_max_frame_bytes(),
            });

        let result = decoder.decode_eof(&mut input);
        assert!(result.is_err(), "Expected error when no header delimiter");

        // Verify the error indicates it cannot continue
        let err = result.unwrap_err();
        assert!(
            !err.can_continue(),
            "Error should not be continuable when skip_on_error=false"
        );
    }

    #[test]
    fn decode_invalid_snappy_data_with_skip_on_error_true() {
        let header = b"metadata";
        let invalid_compressed = b"this is not valid snappy data";

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(invalid_compressed);

        let cfg = StrataSnappyDecoderOptions::default();
        let mut decoder = StrataSnappyDecoder::new(cfg);
        let result = decoder.decode_eof(&mut input);

        assert!(result.is_err(), "Decompression should fail");
        assert!(!result.unwrap_err().can_continue());
    }

    fn gen_random_str<R: rand::Rng>(n: u16, rng: &mut R) -> String {
        gen_random_str_len(rng.gen_range(1..=n), rng)
    }

    fn gen_random_str_len<R: rand::Rng>(n: u16, rng: R) -> String {
        use rand::distributions::Alphanumeric;
        rng
            .sample_iter(&Alphanumeric)
            .take(n as usize)
            .map(char::from)
            .collect()
    }

    fn hex(data: &[u8]) -> String {
        data.chunks(4).map(hex::encode).join(".")
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(5)]
    #[traced_test]
    fn decode_random(#[case] in_len: usize) {
        let mut rng = rand::thread_rng();
        let seed = rng.next_u64();
        trace!("Using seed {}", seed);
        let mut seed_bytes = BytesMut::from(&seed.to_le_bytes()[..]);
        seed_bytes.resize(32, 0);
        let seed_bytes: [u8; 32] = seed_bytes
            .as_ref()
            .try_into()
            .expect("Bytes length must be exactly 32");
        let mut rng = StdRng::from_seed(seed_bytes);
        let header = b"my hdr";
        let payload_strs = (0..5)
            .map(|_| gen_random_str(5, &mut rng))
            .collect::<Vec<String>>();

        let payload = payload_strs.join("\n").into_bytes();
        let compressed = snap::raw::Encoder::new()
            .compress_vec(&payload)
            .expect("compression failed");

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed);

        trace!(
            "Payload size: {},  header: {}, body: 0x{}, payload: 0x{}",
            input.len(),
            std::str::from_utf8(header).unwrap(),
            hex(&compressed),
            hex(&input));

        let cfg = StrataSnappyDecoderOptions::default();
        let mut decoder = StrataSnappyDecoder::new(cfg);

        let mut in_buff = BytesMut::new();
        let mut out_frames = vec![];
        let chunks = (&input).chunks(in_len);
        let chunks_len = chunks.len();
        for (i, chunk) in chunks.enumerate() {
            in_buff.extend_from_slice(chunk);
            trace!("Feeding buff 0x{}", hex(&in_buff));
            let res = if i == chunks_len - 1 {
                decoder.decode_eof(&mut in_buff)
            } else {
                decoder.decode(&mut in_buff)
            };
            match res {
                Ok(Some(r)) => {
                    let new_frame = std::str::from_utf8(&r)
                        .unwrap()
                        .split('\n')
                        .map(|s| s.into())
                        .collect::<Vec<String>>();
                    if new_frame.len() > 0 {
                        out_frames.push(new_frame);
                    }
                },
                Ok(None) => {},
                Err(e) => panic!("decoder failed: {}", e),
            };
        }

        let mut data = vec![];
        for frame in out_frames {
            assert_eq!(frame[0], "my hdr".to_string());
            for line in frame[1..].iter() {
                data.push(line.to_string());
            }
        }

        assert_eq!(data, payload_strs);

        assert_eq!(decoder.decode_eof(&mut in_buff).unwrap(), None);
        assert_eq!(decoder.decode_eof(&mut in_buff).unwrap(), None);
    }
}
