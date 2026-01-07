use bytes::{Buf, BufMut, Bytes, BytesMut};
use memchr::memchr;
use snafu::Snafu;
use tokio_util::codec::Decoder;
use tracing::{trace, warn};
use vector_config::configurable_component;

use super::{BoxedFramingError, FramingError};
use crate::StreamDecodingError;

#[derive(Debug, Snafu)]
pub enum StrataSnappyDecoderError {
    #[snafu(display("Failed to decompress snappy data: {}", source))]
    DecompressionFailed {
        source: snap::Error,
        skip_on_error: bool,
    },

    #[snafu(display("Decompressed data size {} exceeds maximum limit {}", actual_size, max_size))]
    DecompressionBufferSizeExceeded {
        actual_size: usize,
        max_size: usize,
        skip_on_error: bool,
    },

    #[snafu(display("Invalid Strata log format: no header newline found"))]
    NoHeaderDelimiter { skip_on_error: bool },
}

impl FramingError for StrataSnappyDecoderError {
    fn as_any(&self) -> &dyn std::any::Any {
        self as &dyn std::any::Any
    }
}

impl StreamDecodingError for StrataSnappyDecoderError {
    fn can_continue(&self) -> bool {
        // Return the skip_on_error flag from the error
        // When true, skip the current record and continue with the next
        // When false, stop processing entirely
        match self {
            StrataSnappyDecoderError::DecompressionFailed { skip_on_error, .. } => *skip_on_error,
            StrataSnappyDecoderError::DecompressionBufferSizeExceeded { skip_on_error, .. } => {
                *skip_on_error
            }
            StrataSnappyDecoderError::NoHeaderDelimiter { skip_on_error } => *skip_on_error,
        }
    }
}

#[configurable_component]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StrataSnappyDecoderConfig {
    /// Options for the Strata Snappy decoder.
    #[serde(default, skip_serializing_if = "vector_core::serde::is_default")]
    pub strata_snappy: StrataSnappyDecoderOptions,
}

/// Default maximum decompressed size (256 MB).
fn default_max_decompressed_size() -> Option<usize> {
    Some(268_435_456)
}

const fn default_skip_on_error() -> bool {
    true
}

#[configurable_component]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StrataSnappyDecoderOptions {
    /// The maximum size of the decompressed data in bytes.
    ///
    /// This is a safety limit to prevent excessive memory usage from malformed
    /// or malicious compressed data. The buffer grows dynamically as needed during
    /// decompression up to this limit.
    ///
    /// Default: 268435456 (256 MB)
    #[serde(
        default = "default_max_decompressed_size",
        skip_serializing_if = "vector_core::serde::is_default"
    )]
    pub max_decompressed_size: Option<usize>,

    /// Whether to skip and continue processing when decompression errors occur.
    ///
    /// When true, errors (corrupt data, buffer size exceeded, invalid format) are logged
    /// and the current record is skipped, allowing processing to continue with the next record.
    ///
    /// When false, errors will stop the entire source from processing further data.
    ///
    /// Default: true
    #[serde(
        default = "default_skip_on_error",
        skip_serializing_if = "vector_core::serde::is_default"
    )]
    pub skip_on_error: bool,
}

impl Default for StrataSnappyDecoderOptions {
    fn default() -> Self {
        Self {
            max_decompressed_size: default_max_decompressed_size(),
            skip_on_error: default_skip_on_error(),
        }
    }
}

impl StrataSnappyDecoderConfig {
    pub fn new() -> Self {
        Default::default()
    }

    pub const fn new_with_max_size(max_decompressed_size: usize) -> Self {
        Self {
            strata_snappy: StrataSnappyDecoderOptions {
                max_decompressed_size: Some(max_decompressed_size),
                skip_on_error: default_skip_on_error(),
            },
        }
    }
    
    pub const fn build(&self) -> StrataSnappyDecoder {
        StrataSnappyDecoder::new(
            self.strata_snappy.max_decompressed_size,
            self.strata_snappy.skip_on_error,
        )
    }
}

/// Strata log format where each file consists of:
/// 1. A header line (terminated by newline character, ASCII 10)
/// 2. Snappy-compressed payload containing the actual log data
///
/// The decoder preserves the header metadata and decompresses the payload, returning
/// the header as the first line followed by the decompressed log entries enriched with header metadata
#[derive(Debug, Clone)]
pub struct StrataSnappyDecoder {
    header_extracted: bool,
    header: Option<Bytes>,
    max_decompressed_size: Option<usize>,
    skip_on_error: bool,
}

impl StrataSnappyDecoder {
    pub const fn new(max_decompressed_size: Option<usize>, skip_on_error: bool) -> Self {
        Self {
            header_extracted: false,
            header: None,
            max_decompressed_size,
            skip_on_error,
        }
    }

    /// Extract and preserve the header (first line until newline) from the buffer.
    /// Returns true if header was extracted, false if no newline found yet.
    fn extract_header(&mut self, buf: &mut BytesMut) -> bool {
        if self.header_extracted {
            return true;
        }

        match memchr(b'\n', buf) {
            Some(newline_idx) => {
                // Extract the header (without the newline)
                let header_bytes = buf.split_to(newline_idx).freeze();
                buf.advance(1); // Skip the newline itself

                trace!(
                    message = "Extracted Strata log header.",
                    header_size = header_bytes.len()
                );

                self.header = Some(header_bytes);
                self.header_extracted = true;
                true
            }
            None => false,
        }
    }

    fn decompress(&self, compressed: &[u8]) -> Result<Bytes, BoxedFramingError> {
        trace!(
            message = "Decompressing Strata log payload.",
            compressed_size = compressed.len()
        );

        let decompressed = snap::raw::Decoder::new()
            .decompress_vec(compressed)
            .map_err(|source| {
                warn!(
                    message = "Failed to decompress snappy data.",
                    compressed_size = compressed.len(),
                    error = %source,
                    internal_log_rate_limit = true
                );
                StrataSnappyDecoderError::DecompressionFailed {
                    source,
                    skip_on_error: self.skip_on_error,
                }
            })?;

        if let Some(max_size) = self.max_decompressed_size {
            if decompressed.len() > max_size {
                warn!(
                    message = "Decompressed data exceeds maximum size limit.",
                    decompressed_size = decompressed.len(),
                    max_size = max_size,
                    internal_log_rate_limit = true
                );
                return Err(StrataSnappyDecoderError::DecompressionBufferSizeExceeded {
                    actual_size: decompressed.len(),
                    max_size,
                    skip_on_error: self.skip_on_error,
                }
                    .into());
            }
        }

        trace!(
            message = "Successfully decompressed Strata log payload.",
            decompressed_size = decompressed.len()
        );

        Ok(Bytes::from(decompressed))
    }
}

impl Default for StrataSnappyDecoder {
    fn default() -> Self {
        Self::new(None, default_skip_on_error())
    }
}

impl Decoder for StrataSnappyDecoder {
    type Item = Bytes;
    type Error = BoxedFramingError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // For streaming sources, we need to wait for a complete record.
        // Since we can't determine record boundaries in the compressed data,
        // we return None and wait for decode_eof or more sophisticated

        if !self.header_extracted {
            if !self.extract_header(src) {
                // No newline found yet, need more data
                return Ok(None);
            }
        }

        Ok(None)
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if !self.header_extracted {
            if !self.extract_header(src) {
                if src.is_empty() {
                    return Ok(None);
                }
                // No newline found in entire buffer - invalid format
                warn!(
                    message = "Invalid Strata log format: no header newline found.",
                    buffer_size = src.len(),
                    internal_log_rate_limit = true
                );
                return Err(StrataSnappyDecoderError::NoHeaderDelimiter {
                    skip_on_error: self.skip_on_error,
                }
                    .into());
            }
        }

        // If buffer is empty after extracting header, nothing to decompress
        if src.is_empty() {
            return Ok(None);
        }

        // Decompress the remaining data
        let compressed = src.split().freeze();
        let decompressed = self.decompress(&compressed)?;

        // Combine header and decompressed data
        // Output format: header_line\ndecompressed_data
        let header = self.header.as_ref().expect("header should be extracted");
        let mut output = BytesMut::with_capacity(header.len() + 1 + decompressed.len());
        output.extend_from_slice(header);
        output.put_u8(b'\n');
        output.extend_from_slice(&decompressed);

        // Reset state for potential next record
        self.header_extracted = false;
        self.header = None;

        Ok(Some(output.freeze()))
    }
}

#[cfg(test)]
mod tests {
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

        let mut decoder = StrataSnappyDecoder::new(None, true);

        // decode() should return None (waiting for EOF)
        assert_eq!(decoder.decode(&mut input).unwrap(), None);

        // decode_eof() should return header + decompressed payload
        let result = decoder.decode_eof(&mut input).unwrap();
        assert!(result.is_some());

        let output = result.unwrap();
        // Output should be: header\npayload
        let expected = format!("{}\n{}",
                               std::str::from_utf8(header).unwrap(),
                               std::str::from_utf8(payload).unwrap()
        );
        assert_eq!(output, Bytes::from(expected));
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

        let mut decoder = StrataSnappyDecoder::new(None, true);

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

        let mut decoder = StrataSnappyDecoder::new(None, true);

        let result = decoder.decode_eof(&mut input).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn decode_no_header_newline() {
        let input_data = b"no newline here just compressed data";
        let mut input = BytesMut::from(&input_data[..]);

        let mut decoder = StrataSnappyDecoder::new(None, true);

        let result = decoder.decode_eof(&mut input);
        assert!(result.is_err());
    }

    #[test]
    fn decode_with_max_size_limit() {
        let header = b"metadata";
        let large_payload = vec![b'A'; 10000];

        let compressed = snap::raw::Encoder::new()
            .compress_vec(&large_payload)
            .expect("compression failed");

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed);

        // Set max size to 5000 (less than payload size)
        let mut decoder = StrataSnappyDecoder::new(Some(5000), true);

        let result = decoder.decode_eof(&mut input);
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
        let mut decoder = StrataSnappyDecoder::new(Some(1000), true);

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

        let mut decoder = StrataSnappyDecoder::new(None, true);

        let result = decoder.decode_eof(&mut input);
        assert!(result.is_err());
    }

    #[test]
    fn decode_multiple_records_sequentially() {
        // First record
        let header1 = b"record1";
        let payload1 = b"First record data";
        let compressed1 = snap::raw::Encoder::new()
            .compress_vec(payload1)
            .expect("compression failed");

        let mut input1 = BytesMut::new();
        input1.extend_from_slice(header1);
        input1.put_u8(b'\n');
        input1.extend_from_slice(&compressed1);

        let mut decoder = StrataSnappyDecoder::new(None, true);

        let result1 = decoder.decode_eof(&mut input1).unwrap();
        let output1 = result1.unwrap();
        assert!(std::str::from_utf8(&output1).unwrap().contains("record1"));
        assert!(std::str::from_utf8(&output1).unwrap().contains("First record data"));

        // Second record (decoder state should be reset)
        let header2 = b"record2";
        let payload2 = b"Second record data";
        let compressed2 = snap::raw::Encoder::new()
            .compress_vec(payload2)
            .expect("compression failed");

        let mut input2 = BytesMut::new();
        input2.extend_from_slice(header2);
        input2.put_u8(b'\n');
        input2.extend_from_slice(&compressed2);

        let result2 = decoder.decode_eof(&mut input2).unwrap();
        let output2 = result2.unwrap();
        assert!(std::str::from_utf8(&output2).unwrap().contains("record2"));
        assert!(std::str::from_utf8(&output2).unwrap().contains("Second record data"));
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
        let mut decoder = StrataSnappyDecoder::new(None, false);

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
        let mut decoder = StrataSnappyDecoder::new(Some(5000), false);

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
        let mut decoder = StrataSnappyDecoder::new(None, false);

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

        // skip_on_error = true - errors should be continuable
        let mut decoder = StrataSnappyDecoder::new(None, true);

        let result = decoder.decode_eof(&mut input);
        assert!(result.is_err(), "Decompression should still fail");

        // Verify the error indicates it can continue
        let err = result.unwrap_err();
        assert!(
            err.can_continue(),
            "Error should be continuable when skip_on_error=true"
        );
    }
}
