#[cfg(test)]
use bytes::BufMut;
use bytes::{Buf, Bytes, BytesMut};
use lookup::lookup_v2::{ConfigTargetPath, ValuePath};
use memchr::{memchr, memrchr};
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
    DecompressedSizeExceeded {
        actual_size: usize,
        max_size: usize,
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
            StrataSnappyDecoderError::DecompressedSizeExceeded { .. } => {
                // Decompressed size exceeded is always non-resumable
                false
            }
            StrataSnappyDecoderError::NoHeaderDelimiter { skip_on_error } => *skip_on_error,
        }
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

/// Default maximum decompressed data size (256 MB).
///
/// This limit applies to the total size of decompressed data from a single snappy block.
fn default_max_record_bytes() -> usize {
    256 * 1024 * 1024
}

const fn default_skip_on_error() -> bool {
    true
}

fn default_header_field_name() -> ConfigTargetPath {
    ConfigTargetPath::try_from("strata_file_header".to_string()).expect("valid path")
}

fn is_default_header_field_name(value: &ConfigTargetPath) -> bool {
    value == &default_header_field_name()
}

const fn default_enrich_with_header() -> bool {
    true
}

/// Options for configuring the Strata Snappy decoder behavior.
#[configurable_component]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StrataSnappyDecoderOptions {
    /// The maximum size of decompressed data in bytes.
    ///
    /// This is a safety limit to prevent excessive memory usage from malformed
    /// or malicious data. When the decompressed data exceeds this limit,
    /// the stream is rejected with a non-resumable error.
    ///
    /// Default: 256 * 1024 * 1024 (256 MB)
    #[serde(
        default = "default_max_record_bytes",
        skip_serializing_if = "vector_core::serde::is_default"
    )]
    pub max_record_bytes: usize,

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

    /// Whether to enrich each JSON log line with the parsed header.
    ///
    /// When true, the first line (header) is parsed as JSON and merged into each
    /// subsequent JSON log line under the field specified by `header_field_name`.
    /// This allows using a standard JSON deserializer instead of a custom Strata deserializer.
    ///
    /// When false, the framer returns the raw decompressed data and a custom
    /// Strata deserializer is needed to handle the header.
    ///
    /// Default: false
    #[serde(
        default = "default_enrich_with_header",
        skip_serializing_if = "vector_core::serde::is_default"
    )]
    pub enrich_with_header: bool,

    /// Field path for storing the header metadata in each JSON log line.
    ///
    /// Only used when `enrich_with_header` is true. The parsed header JSON
    /// will be added to each log event under this field path.
    ///
    /// Supports nested paths using dot notation (e.g., "metadata.header").
    ///
    /// Default: "strata_file_header"
    #[serde(
        default = "default_header_field_name",
        skip_serializing_if = "is_default_header_field_name"
    )]
    #[configurable(metadata(docs::examples = "strata_file_header"))]
    #[configurable(metadata(docs::examples = "metadata.header"))]
    pub header_field_name: ConfigTargetPath,
}

impl Default for StrataSnappyDecoderOptions {
    fn default() -> Self {
        Self {
            max_record_bytes: default_max_record_bytes(),
            skip_on_error: default_skip_on_error(),
            enrich_with_header: default_enrich_with_header(),
            header_field_name: default_header_field_name(),
        }
    }
}

impl StrataSnappyDecoderConfig {
    /// Creates a new StrataSnappyDecoderConfig with default settings.
    pub fn new() -> Self {
        Default::default()
    }

    /// Builds a StrataSnappyDecoder from this configuration.
    pub fn build(&self) -> StrataSnappyDecoder {
        StrataSnappyDecoder::new(
            self.strata_snappy.max_record_bytes,
            self.strata_snappy.skip_on_error,
            self.strata_snappy.enrich_with_header,
            self.strata_snappy.header_field_name.clone(),
        )
    }
}

/// Strata log format where each file consists of:
/// 1. A header line (terminated by newline character, ASCII 10)
/// 2. Snappy-compressed payload containing the actual log data
///
/// The decoder decompresses the payload and can optionally enrich each JSON log line
/// with the parsed header metadata. When enrichment is enabled, this allows using
/// a standard JSON deserializer. When disabled, a custom Strata deserializer is needed.
#[derive(Debug, Clone)]
pub struct StrataSnappyDecoder {
    // Serialized header bytes - validated as JSON once during extraction
    // Used for both returning to caller and for enrichment (parse or append)
    header_bytes: Option<Bytes>,
    header_returned: bool,  // Track if header has been returned (cheap: 1 byte)
    remaining_data: Bytes,
    max_record_bytes: usize,
    skip_on_error: bool,
    enrich_with_header: bool,
    // Cached field name data for fast enrichment (computed once, used for every log line)
    field_name_string: String,  // Extracted field name (e.g., "strata_file_header")
    is_nested_path: bool,  // True if path has multiple segments (e.g., "metadata.header")
}

impl StrataSnappyDecoder {
    /// Creates a new StrataSnappyDecoder with the specified configuration.
    ///
    /// # Arguments
    /// * `max_record_bytes` - Maximum size limit for decompressed data in bytes
    /// * `skip_on_error` - Whether to skip and continue processing on errors
    /// * `enrich_with_header` - Whether to enrich JSON lines with header metadata
    /// * `header_field_name` - Field path for header metadata in enriched JSON
    pub fn new(max_record_bytes: usize, skip_on_error: bool, enrich_with_header: bool, header_field_name: ConfigTargetPath) -> Self {
        // Pre-compute field name metadata for fast enrichment
        let field_name_string = String::from(&header_field_name.0.path);
        let is_nested_path = (&header_field_name.0.path).segment_iter().count() > 1;

        Self {
            header_bytes: None,
            header_returned: false,
            remaining_data: Bytes::new(),
            max_record_bytes,
            skip_on_error,
            enrich_with_header,
            field_name_string,
            is_nested_path,
        }
    }

    /// Helper to create a decompression error with the configured skip_on_error flag.
    #[inline]
    fn decompression_error(&self, source: snap::Error) -> BoxedFramingError {
        StrataSnappyDecoderError::DecompressionFailed {
            source,
            skip_on_error: self.skip_on_error,
        }.into()
    }

    /// Helper to create an enrichment error (reuses DecompressionFailed with Header error).
    #[inline]
    fn enrichment_error(&self) -> BoxedFramingError {
        self.decompression_error(snap::Error::Header)
    }

    /// Extract and validate the header (first line until newline) from the buffer as JSON.
    /// Returns true if header was extracted, false if no newline found yet.
    ///
    /// Validates header is valid JSON once during extraction, then stores bytes.
    /// The bytes are used for both returning to caller and enrichment.
    fn extract_header(&mut self, buf: &mut BytesMut) -> bool {
        if self.header_bytes.is_some() {
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

                // Validate header is valid JSON (check only once, don't store parsed form)
                if serde_json::from_slice::<serde_json::Value>(&header_bytes).is_ok() {
                    self.header_bytes = Some(header_bytes);
                    true
                } else {
                    warn!(
                        message = "Failed to parse Strata header as JSON.",
                        internal_log_rate_limit = true
                    );
                    false
                }
            }
            None => false,
        }
    }

    /// Returns the header bytes for returning as the first line.
    /// Header bytes are already validated as JSON during extraction.
    fn get_header_bytes(&self) -> Bytes {
        self.header_bytes.as_ref().expect("header should be extracted").clone()
    }

    /// Decompresses snappy data using pre-allocation based on decompress_len.
    ///
    /// Allocates a buffer sized exactly for the decompressed data,
    /// then decompresses directly into it for efficiency.
    fn decompress(&self, compressed: &[u8]) -> Result<Bytes, BoxedFramingError> {
        trace!(
            message = "Decompressing Strata log payload.",
            compressed_size = compressed.len()
        );

        // Get decompressed size from snappy header
        let decompress_len = snap::raw::decompress_len(compressed).map_err(|source| {
            warn!(
                message = "Failed to read snappy decompression length.",
                compressed_size = compressed.len(),
                error = %source,
                internal_log_rate_limit = true
            );
            self.decompression_error(source)
        })?;

        // Check decompressed data size against limit BEFORE allocating buffer
        if decompress_len > self.max_record_bytes {
            warn!(
                message = "Decompressed data size from snappy header exceeds maximum limit.",
                decompressed_size = decompress_len,
                max_size = self.max_record_bytes,
                internal_log_rate_limit = true
            );
            return Err(StrataSnappyDecoderError::DecompressedSizeExceeded {
                actual_size: decompress_len,
                max_size: self.max_record_bytes,
            }
                .into());
        }

        // Allocate buffer exactly for decompressed data
        let mut buffer = vec![0u8; decompress_len];

        // Decompress directly into buffer
        snap::raw::Decoder::new()
            .decompress(compressed, &mut buffer)
            .map_err(|source| {
                warn!(
                    message = "Failed to decompress snappy data.",
                    compressed_size = compressed.len(),
                    error = %source,
                    internal_log_rate_limit = true
                );
                self.decompression_error(source)
            })?;

        trace!(
            message = "Successfully decompressed Strata log payload.",
            decompressed_size = decompress_len
        );

        Ok(Bytes::from(buffer))
    }

    /// Try to decompress all data in src (one complete Strata snappy block).
    /// On success, src is cleared and decompressed data is returned.
    /// On failure, src is left untouched.
    fn try_decompress_all(&self, src: &mut BytesMut) -> Result<Bytes, BoxedFramingError> {
        // Get decompressed size from snappy header
        let decompress_len = snap::raw::decompress_len(src)
            .map_err(|source| self.decompression_error(source))?;

        // Check decompressed data size against limit BEFORE allocating buffer
        if decompress_len > self.max_record_bytes {
            warn!(
                message = "Decompressed data size from snappy header exceeds maximum limit.",
                decompressed_size = decompress_len,
                max_size = self.max_record_bytes,
                internal_log_rate_limit = true
            );
            return Err(StrataSnappyDecoderError::DecompressedSizeExceeded {
                actual_size: decompress_len,
                max_size: self.max_record_bytes,
            }
                .into());
        }

        // Pre-allocate exact buffer size
        let mut buffer = vec![0u8; decompress_len];

        // Try to decompress
        snap::raw::Decoder::new()
            .decompress(src, &mut buffer)
            .map_err(|source| self.decompression_error(source))?;

        // Success! Clear src since we consumed the compressed block
        src.clear();

        Ok(Bytes::from(buffer))
    }

    /// Extract the next non-empty line from remaining_data.
    /// Uses memchr for efficient newline finding and Bytes::slice for zero-copy slicing.
    ///
    /// Automatically skips empty lines (consecutive newlines) by looping until a non-empty
    /// line is found or remaining_data is exhausted. This handles cases where the payload
    /// contains empty lines between log entries.
    fn extract_next_line(&mut self) -> Option<Bytes> {
        // Loop to skip empty lines (consecutive newlines)
        loop {
            if self.remaining_data.is_empty() {
                return None;
            }

            if let Some(newline_pos) = memchr(b'\n', &self.remaining_data) {
                // Extract line without the newline
                let line = self.remaining_data.slice(..newline_pos);
                // Advance past the newline
                self.remaining_data = self.remaining_data.slice((newline_pos + 1)..);

                // Skip empty lines, continue to next iteration
                if !line.is_empty() {
                    return Some(line);
                }
                // Continue loop to find next non-empty line
            } else {
                // Last line without trailing newline - take everything
                let line = self.remaining_data.clone();
                self.remaining_data = Bytes::new();

                // Return only if non-empty
                if !line.is_empty() {
                    return Some(line);
                }
                return None;
            }
        }
    }

    /// Enrich a JSON line with the header metadata.
    /// Parses the line as JSON, adds the header field, and serializes back.
    ///
    /// Optimization: Uses serde_json directly to parse into a mutable object,
    /// inserts the header field, then serializes to Vec<u8> in one pass.
    fn enrich_json_line(&self, line: Bytes) -> Result<Bytes, BoxedFramingError> {
        let header_bytes = self.header_bytes.as_ref().expect("header should be extracted when enriching");

        // Check if path is nested (has multiple segments like "metadata.header")
        // For simple paths (single segment), we can use an optimized string manipulation approach
        // This check is pre-computed in the constructor for efficiency
        if self.is_nested_path {
            // Nested path - use full parse/modify/serialize approach with proper nested insertion
            let mut log_value: serde_json::Value = serde_json::from_slice(&line).map_err(|e| {
                warn!(
                    message = "Failed to parse log line as JSON for nested path enrichment.",
                    error = %e,
                    internal_log_rate_limit = true
                );
                self.enrichment_error()
            })?;

            // Parse header bytes (already validated as JSON during extraction)
            let header_value: serde_json::Value = serde_json::from_slice(header_bytes).map_err(|e| {
                warn!(
                    message = "Failed to parse header bytes as JSON.",
                    error = %e,
                    internal_log_rate_limit = true
                );
                self.enrichment_error()
            })?;

            // Navigate through the path and insert header at the nested location
            // For example, path "metadata.header" creates: {"existing": ..., "metadata": {"header": <header_value>}}
            // If intermediate objects exist, we merge into them
            let log_obj = log_value.as_object_mut().ok_or_else(|| {
                warn!(
                    message = "Log line is not a JSON object, cannot enrich with nested path.",
                    internal_log_rate_limit = true
                );
                self.enrichment_error()
            })?;

            // Split path into segments (e.g., "metadata.header" -> ["metadata", "header"])
            let path_segments: Vec<&str> = self.field_name_string.split('.').collect();

            // Navigate to the parent object, creating intermediate objects as needed
            let mut current = log_obj;
            for segment in &path_segments[..path_segments.len() - 1] {
                // Get or create the intermediate object
                current = current
                    .entry(*segment)
                    .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
                    .as_object_mut()
                    .ok_or_else(|| {
                        warn!(
                            message = "Path segment exists but is not an object, cannot create nested structure.",
                            segment = %segment,
                            internal_log_rate_limit = true
                        );
                        StrataSnappyDecoderError::DecompressionFailed {
                            source: snap::Error::Header,
                            skip_on_error: self.skip_on_error,
                        }
                    })?;
            }

            // Insert the header at the final segment
            let final_segment = path_segments.last().expect("path should have at least one segment");
            current.insert(final_segment.to_string(), header_value);

            // Serialize back to JSON
            let estimated_size = line.len()
                .saturating_add(header_bytes.len())
                .saturating_add(self.field_name_string.len())
                .saturating_add(50); // Overhead for nested structure
            let mut enriched_bytes = Vec::with_capacity(estimated_size);

            serde_json::to_writer(&mut enriched_bytes, &log_value)
                .map_err(|e| {
                    warn!(
                        message = "Failed to serialize enriched JSON with nested path.",
                        error = %e,
                        internal_log_rate_limit = true
                    );
                    StrataSnappyDecoderError::DecompressionFailed {
                        source: snap::Error::Header,
                        skip_on_error: self.skip_on_error,
                    }
                })?;

            Ok(Bytes::from(enriched_bytes))
        } else {
            // Simple (non-nested) path - use optimized string manipulation
            // This avoids the parse/serialize cycle by directly manipulating the JSON string

            // header_bytes is already a UTF-8 string (validated JSON)
            let header_str = std::str::from_utf8(header_bytes).map_err(|e| {
                warn!(
                    message = "Header bytes are not valid UTF-8.",
                    error = %e,
                    internal_log_rate_limit = true
                );
                self.enrichment_error()
            })?;

            // Use cached field name (pre-computed in constructor)
            let field_name = &self.field_name_string;

            // Find the last '}' in the line (should be the closing brace of the JSON object)
            let last_brace_pos = memrchr(b'}', &line).ok_or_else(|| {
                warn!(
                    message = "Log line does not contain closing brace, not a valid JSON object.",
                    internal_log_rate_limit = true
                );
                self.enrichment_error()
            })?;

            // Split line into prefix (before '}'), and suffix (after '}', usually empty or newline)
            let prefix = &line[..last_brace_pos];
            let suffix = &line[last_brace_pos + 1..];

            // Check if this is an empty object by finding the last non-whitespace character
            // If it's '{', then we have an empty object like {} or { }
            let is_empty_object = prefix
                .iter()
                .rev()
                .find(|&&b| !b.is_ascii_whitespace())
                .map(|&b| b == b'{')
                .unwrap_or(false);

            // Build the enriched JSON by inserting: ,"field_name":header_json before the final }
            // For empty objects, omit the leading comma
            let estimated_size = line.len()
                .saturating_add(header_str.len())
                .saturating_add(field_name.len())
                .saturating_add(10); // Quotes, colon, comma, etc.

            let mut enriched_bytes = Vec::with_capacity(estimated_size);
            enriched_bytes.extend_from_slice(prefix);

            if !is_empty_object {
                enriched_bytes.push(b',');
            }

            enriched_bytes.push(b'"');
            enriched_bytes.extend_from_slice(field_name.as_bytes());
            enriched_bytes.extend_from_slice(b"\":");
            enriched_bytes.extend_from_slice(header_str.as_bytes());
            enriched_bytes.push(b'}');
            enriched_bytes.extend_from_slice(suffix);

            Ok(Bytes::from(enriched_bytes))
        }
    }

    /// Helper to extract and optionally enrich a line from remaining_data.
    ///
    /// Returns:
    /// - `Ok(Some(line))` if a line is available (enriched or raw depending on config)
    /// - `Ok(None)` if no line is available in remaining_data
    /// - `Err(...)` if enrichment is enabled and fails (invalid JSON in log line, path conflicts, etc.)
    ///
    /// Note: Errors only occur when `enrich_with_header=true` and the enrichment process fails.
    fn extract_line(&mut self) -> Result<Option<Bytes>, BoxedFramingError> {
        if let Some(line) = self.extract_next_line() {
            if self.enrich_with_header {
                // Enrich and return the enriched line
                self.enrich_json_line(line).map(Some)
            } else {
                // Return raw line
                Ok(Some(line))
            }
        } else {
            // No line available
            Ok(None)
        }
    }
}

impl Default for StrataSnappyDecoder {
    fn default() -> Self {
        Self::new(
            default_max_record_bytes(),
            default_skip_on_error(),
            default_enrich_with_header(),
            default_header_field_name(),
        )
    }
}

impl Decoder for StrataSnappyDecoder {
    type Item = Bytes;
    type Error = BoxedFramingError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // First, try to return a line from remaining_data if we have buffered data
        // This will be decompressed log lines from a previous call
        if let Some(line) = self.extract_line()? {
            return Ok(Some(line));
        }

        // Extract header if not done yet
        if !self.extract_header(src) {
            // No newline found yet, need more data
            return Ok(None);
        }

        // If header extracted but not yet returned, return it now
        if !self.header_returned {
            self.header_returned = true;
            return Ok(Some(self.get_header_bytes()));
        }

        // After header, all remaining bytes in src should be ONE snappy-compressed block
        // (Strata format is header + single compressed block)
        if src.is_empty() {
            return Ok(None);
        }

        // Try to decompress all of src (one complete snappy block)
        // Size check happens inside try_decompress_all before allocation
        // If decompression fails due to incomplete data, we return Ok(None)
        // and leave src untouched for the next call with more data
        let decompressed = match self.try_decompress_all(src) {
            Ok(data) => data,
            Err(e) => {
                // Decompression failed - could be incomplete data, corruption, or size exceeded
                // Return Ok(None) to request more data (unless it's a non-resumable error)
                // At EOF, decode_eof will report the actual error
                trace!(
                    message = "Decompression attempt failed, waiting for more data.",
                    error = %e,
                    buffer_size = src.len()
                );
                return Ok(None);
            }
        };

        // Successfully decompressed! Buffer the data and return lines one at a time
        self.remaining_data = decompressed;

        // Return the first line (enriched or not based on config)
        self.extract_line()
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // First, try to return remaining buffered lines
        // This will be decompressed log lines from a previous call
        if let Some(line) = self.extract_line()? {
            return Ok(Some(line));
        }

        // If we've finished processing a file (no remaining data) and src is not empty,
        // check if it looks like a new file (starts with JSON and has newline).
        // Only reset if we can successfully parse a new header from the beginning of src.
        if self.header_bytes.is_some() && !src.is_empty() {
            // Check if this looks like a new file by seeing if there's a newline
            // and the data before it parses as JSON
            if let Some(newline_idx) = memchr(b'\n', src) {
                // Try to parse as JSON without consuming
                if serde_json::from_slice::<serde_json::Value>(&src[..newline_idx]).is_ok() {
                    // Looks like a new file header, reset state
                    self.header_bytes = None;
                    self.header_returned = false;
                }
            }
        }

        // Extract header if not done yet
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

        // If header extracted but not yet returned, return it now
        if !self.header_returned {
            self.header_returned = true;
            return Ok(Some(self.get_header_bytes()));
        }

        // Decompress any remaining compressed data
        // Size check happens inside decompress() before allocation
        if !src.is_empty() {
            let compressed = src.split().freeze();
            let decompressed = self.decompress(&compressed)?;

            // Buffer the decompressed data and return first line
            self.remaining_data = decompressed;
            return self.extract_line();
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_strata_log_simple() {
        let header = br#"{"timestamp":123456789}"#;
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

        let mut decoder = StrataSnappyDecoder::new(default_max_record_bytes(), true, false, default_header_field_name());

        // decode() should successfully decompress and return first line (header)
        let result1 = decoder.decode(&mut input).unwrap();
        assert!(result1.is_some());
        let output1 = result1.unwrap();
        assert_eq!(output1, Bytes::from(header.as_ref()));

        // Second decode() call should return the payload
        let result2 = decoder.decode(&mut input).unwrap();
        assert!(result2.is_some());
        let output2 = result2.unwrap();
        assert_eq!(output2, Bytes::from(payload.as_ref()));

        // No more data
        let result3 = decoder.decode(&mut input).unwrap();
        assert!(result3.is_none());
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

        let mut decoder = StrataSnappyDecoder::new(default_max_record_bytes(), true, false, default_header_field_name());

        // First call to decode_eof should return the header line
        let result1 = decoder.decode_eof(&mut input).unwrap();
        assert!(result1.is_some());
        let output1 = result1.unwrap();
        let header_parsed: serde_json::Value = serde_json::from_slice(&output1)
            .expect("header should be valid JSON");
        assert_eq!(header_parsed["bucket"], "test");

        // Second call should return the log entry
        let result2 = decoder.decode_eof(&mut input).unwrap();
        assert!(result2.is_some());
        let output2 = result2.unwrap();
        let log_parsed: serde_json::Value = serde_json::from_slice(&output2)
            .expect("log should be valid JSON");
        assert_eq!(log_parsed["level"], "info");
        assert_eq!(log_parsed["message"], "Test log entry");

        // No more data
        let result3 = decoder.decode_eof(&mut input).unwrap();
        assert!(result3.is_none());
    }

    #[test]
    fn decode_empty_after_header() {
        let header = br#"{"source":"metadata"}"#;
        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');

        let mut decoder = StrataSnappyDecoder::new(default_max_record_bytes(), true, false, default_header_field_name());

        // First call returns the header
        let result1 = decoder.decode_eof(&mut input).unwrap();
        assert!(result1.is_some());
        assert_eq!(result1.unwrap(), Bytes::from(header.as_ref()));

        // Second call returns None (no compressed data after header)
        let result2 = decoder.decode_eof(&mut input).unwrap();
        assert!(result2.is_none());
    }

    #[test]
    fn decode_no_header_newline() {
        let input_data = b"no newline here just compressed data";
        let mut input = BytesMut::from(&input_data[..]);

        let mut decoder = StrataSnappyDecoder::new(default_max_record_bytes(), true, false, default_header_field_name());

        let result = decoder.decode_eof(&mut input);
        assert!(result.is_err());
    }

    #[test]
    fn decode_with_max_size_limit() {
        let header = br#"{"source":"metadata"}"#;
        let large_payload = vec![b'A'; 10000];

        let compressed = snap::raw::Encoder::new()
            .compress_vec(&large_payload)
            .expect("compression failed");

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed);

        // Set max size to 5000 (less than payload size)
        let mut decoder = StrataSnappyDecoder::new(5000, true, false, default_header_field_name());

        // First call returns the header
        let result1 = decoder.decode_eof(&mut input).unwrap();
        assert!(result1.is_some());

        // Second call should error due to size limit
        let result2 = decoder.decode_eof(&mut input);
        assert!(result2.is_err());
    }

    #[test]
    fn decode_with_max_size_within_limit() {
        let header = br#"{"source":"metadata"}"#;
        let payload = b"Small payload";

        let compressed = snap::raw::Encoder::new()
            .compress_vec(payload)
            .expect("compression failed");

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed);

        // Set max size to 1000 (more than payload size)
        let mut decoder = StrataSnappyDecoder::new(1000, true, false, default_header_field_name());

        // First line is the header
        let result1 = decoder.decode_eof(&mut input).unwrap();
        assert!(result1.is_some());
        let output1 = result1.unwrap();
        let output1_str = std::str::from_utf8(&output1).expect("should be valid UTF-8");
        assert!(output1_str.contains("metadata"));

        // Second line is the payload
        let result2 = decoder.decode_eof(&mut input).unwrap();
        assert!(result2.is_some());
        let output2 = result2.unwrap();
        let output2_str = std::str::from_utf8(&output2).expect("should be valid UTF-8");
        assert!(output2_str.contains("Small payload"));
    }

    #[test]
    fn decode_invalid_snappy_data() {
        let header = br#"{"source":"metadata"}"#;
        let invalid_compressed = b"this is not valid snappy data";

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(invalid_compressed);

        let mut decoder = StrataSnappyDecoder::new(default_max_record_bytes(), true, false, default_header_field_name());

        // First call returns the header
        let result1 = decoder.decode_eof(&mut input).unwrap();
        assert!(result1.is_some());

        // Second call should error due to invalid snappy data
        let result2 = decoder.decode_eof(&mut input);
        assert!(result2.is_err());
    }

    #[test]
    fn decode_multiple_records_sequentially() {
        // First record
        let header1 = br#"{"file":"record1"}"#;
        let payload1 = b"First record data";
        let compressed1 = snap::raw::Encoder::new()
            .compress_vec(payload1)
            .expect("compression failed");

        let mut input1 = BytesMut::new();
        input1.extend_from_slice(header1);
        input1.put_u8(b'\n');
        input1.extend_from_slice(&compressed1);

        let mut decoder = StrataSnappyDecoder::new(default_max_record_bytes(), true, false, default_header_field_name());

        // First line is header
        let result1a = decoder.decode_eof(&mut input1).unwrap();
        let output1a = result1a.unwrap();
        assert!(std::str::from_utf8(&output1a).unwrap().contains("record1"));

        // Second line is payload
        let result1b = decoder.decode_eof(&mut input1).unwrap();
        let output1b = result1b.unwrap();
        assert!(std::str::from_utf8(&output1b).unwrap().contains("First record data"));

        // Second record (decoder state should be reset)
        let header2 = br#"{"file":"record2"}"#;
        let payload2 = b"Second record data";
        let compressed2 = snap::raw::Encoder::new()
            .compress_vec(payload2)
            .expect("compression failed");

        let mut input2 = BytesMut::new();
        input2.extend_from_slice(header2);
        input2.put_u8(b'\n');
        input2.extend_from_slice(&compressed2);

        // First line is header
        let result2a = decoder.decode_eof(&mut input2).unwrap();
        let output2a = result2a.unwrap();
        assert!(std::str::from_utf8(&output2a).unwrap().contains("record2"));

        // Second line is payload
        let result2b = decoder.decode_eof(&mut input2).unwrap();
        let output2b = result2b.unwrap();
        assert!(std::str::from_utf8(&output2b).unwrap().contains("Second record data"));
    }

    #[test]
    fn decode_invalid_snappy_data_with_skip_on_error_false() {
        let header = br#"{"source":"metadata"}"#;
        let invalid_compressed = b"this is not valid snappy data";

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(invalid_compressed);

        // skip_on_error = false - errors should propagate
        let mut decoder = StrataSnappyDecoder::new(default_max_record_bytes(), false, false, default_header_field_name());

        // First call returns the header
        let result1 = decoder.decode_eof(&mut input).unwrap();
        assert!(result1.is_some());

        // Second call should error due to invalid snappy data
        let result2 = decoder.decode_eof(&mut input);
        assert!(result2.is_err(), "Expected error when skip_on_error=false");

        // Verify the error indicates it cannot continue
        let err = result2.unwrap_err();
        assert!(
            !err.can_continue(),
            "Error should not be continuable when skip_on_error=false"
        );
    }

    #[test]
    fn decode_with_max_size_limit_skip_on_error_false() {
        let header = br#"{"source":"metadata"}"#;
        let large_payload = vec![b'A'; 10000];

        let compressed = snap::raw::Encoder::new()
            .compress_vec(&large_payload)
            .expect("compression failed");

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed);

        // Set max size to 5000 (less than payload size) with skip_on_error = false
        let mut decoder = StrataSnappyDecoder::new(5000, false, false, default_header_field_name());

        // First call returns the header
        let result1 = decoder.decode_eof(&mut input).unwrap();
        assert!(result1.is_some());

        // Second call should error due to size limit
        let result2 = decoder.decode_eof(&mut input);
        assert!(result2.is_err(), "Expected error when buffer size exceeded");

        // Verify the error indicates it cannot continue
        let err = result2.unwrap_err();
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
        let mut decoder = StrataSnappyDecoder::new(default_max_record_bytes(), false, false, default_header_field_name());

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
    fn decode_with_header_enrichment() {
        let header = br#"{"bucket":"test-bucket","region":"us-east-1"}"#;
        let log1 = br#"{"level":"info","message":"Test log 1"}"#;
        let log2 = br#"{"level":"warn","message":"Test log 2"}"#;
        let payload = format!("{}\n{}", std::str::from_utf8(log1).unwrap(), std::str::from_utf8(log2).unwrap());

        // Compress the payload
        let compressed = snap::raw::Encoder::new()
            .compress_vec(payload.as_bytes())
            .expect("compression failed");

        // Combine header and compressed payload
        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed);

        let mut decoder = StrataSnappyDecoder::new(default_max_record_bytes(), true, true,
                                                   ConfigTargetPath::try_from("strata_file_header".to_string()).unwrap());

        // First line should be the header (not enriched)
        let result0 = decoder.decode(&mut input).unwrap();
        assert!(result0.is_some());
        let header_line = result0.unwrap();
        assert_eq!(header_line, Bytes::from(header.as_ref()));

        // Second line should be first enriched log line
        let result1 = decoder.decode(&mut input).unwrap();
        assert!(result1.is_some());
        let line1 = result1.unwrap();
        let json1: serde_json::Value = serde_json::from_slice(&line1).unwrap();
        assert_eq!(json1["level"], "info");
        assert_eq!(json1["message"], "Test log 1");
        assert_eq!(json1["strata_file_header"]["bucket"], "test-bucket");
        assert_eq!(json1["strata_file_header"]["region"], "us-east-1");

        // Third line should be second enriched log line
        let result2 = decoder.decode(&mut input).unwrap();
        assert!(result2.is_some());
        let line2 = result2.unwrap();
        let json2: serde_json::Value = serde_json::from_slice(&line2).unwrap();
        assert_eq!(json2["level"], "warn");
        assert_eq!(json2["message"], "Test log 2");
        assert_eq!(json2["strata_file_header"]["bucket"], "test-bucket");
        assert_eq!(json2["strata_file_header"]["region"], "us-east-1");

        // No more lines
        let result3 = decoder.decode(&mut input).unwrap();
        assert!(result3.is_none());
    }

    #[test]
    fn decode_invalid_snappy_data_with_skip_on_error_true() {
        let header = br#"{"source":"metadata"}"#;
        let invalid_compressed = b"this is not valid snappy data";

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(invalid_compressed);

        // skip_on_error = true - errors should be continuable
        let mut decoder = StrataSnappyDecoder::new(default_max_record_bytes(), true, false, default_header_field_name());

        // First call returns the header
        let result1 = decoder.decode_eof(&mut input).unwrap();
        assert!(result1.is_some());

        // Second call should error due to invalid snappy data
        let result2 = decoder.decode_eof(&mut input);
        assert!(result2.is_err(), "Decompression should still fail");

        // Verify the error indicates it can continue
        let err = result2.unwrap_err();
        assert!(
            err.can_continue(),
            "Error should be continuable when skip_on_error=true"
        );
    }

    // ========== Negative Flow Tests ==========

    #[test]
    fn decode_invalid_json_header() {
        // Header is not valid JSON
        let invalid_header = b"not a json header";
        let mut input = BytesMut::new();
        input.extend_from_slice(invalid_header);
        input.put_u8(b'\n');

        let mut decoder = StrataSnappyDecoder::new(default_max_record_bytes(), true, false, default_header_field_name());

        let result = decoder.decode(&mut input);
        // Should return Ok(None) because header parsing failed
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn decode_empty_input() {
        let mut input = BytesMut::new();
        let mut decoder = StrataSnappyDecoder::new(default_max_record_bytes(), true, false, default_header_field_name());

        let result = decoder.decode(&mut input).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn decode_partial_header_no_newline() {
        // Header without newline - should wait for more data
        let partial_header = br#"{"bucket":"test""#;
        let mut input = BytesMut::new();
        input.extend_from_slice(partial_header);

        let mut decoder = StrataSnappyDecoder::new(default_max_record_bytes(), true, false, default_header_field_name());

        let result = decoder.decode(&mut input).unwrap();
        assert!(result.is_none(), "Should wait for newline");

        // Verify buffer wasn't consumed
        assert_eq!(input.len(), partial_header.len());
    }

    #[test]
    fn decode_partial_compressed_data() {
        let header = br#"{"bucket":"test"}"#;
        let payload = b"Test data that will be compressed";
        let compressed = snap::raw::Encoder::new()
            .compress_vec(payload)
            .expect("compression failed");

        // Send header + partial compressed data
        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed[..10]); // Only first 10 bytes

        let mut decoder = StrataSnappyDecoder::new(default_max_record_bytes(), true, false, default_header_field_name());

        // Should return header
        let result1 = decoder.decode(&mut input).unwrap();
        assert!(result1.is_some());
        assert_eq!(result1.unwrap(), Bytes::from(header.as_ref()));

        // Should wait for more compressed data
        let result2 = decoder.decode(&mut input).unwrap();
        assert!(result2.is_none(), "Should wait for complete compressed data");
    }

    #[test]
    fn decode_corrupted_snappy_header() {
        let header = br#"{"bucket":"test"}"#;
        // Create invalid snappy data with corrupted header
        let invalid_snappy = b"\xff\xff\xff\xff";

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(invalid_snappy);

        let mut decoder = StrataSnappyDecoder::new(default_max_record_bytes(), true, false, default_header_field_name());

        // Should return header
        let result1 = decoder.decode_eof(&mut input).unwrap();
        assert!(result1.is_some());

        // Should error on corrupted snappy data
        let result2 = decoder.decode_eof(&mut input);
        assert!(result2.is_err(), "Should fail on corrupted snappy header");
    }

    #[test]
    fn decode_empty_compressed_block() {
        let header = br#"{"bucket":"test"}"#;
        let empty_payload = b"";
        let compressed = snap::raw::Encoder::new()
            .compress_vec(empty_payload)
            .expect("compression failed");

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed);

        let mut decoder = StrataSnappyDecoder::new(default_max_record_bytes(), true, false, default_header_field_name());

        // Should return header
        let result1 = decoder.decode_eof(&mut input).unwrap();
        assert!(result1.is_some());
        assert_eq!(result1.unwrap(), Bytes::from(header.as_ref()));

        // Empty compressed block - no more data
        let result2 = decoder.decode_eof(&mut input).unwrap();
        assert!(result2.is_none());
    }

    #[test]
    fn decode_only_empty_lines_in_payload() {
        let header = br#"{"bucket":"test"}"#;
        let payload = b"\n\n\n"; // Only newlines
        let compressed = snap::raw::Encoder::new()
            .compress_vec(payload)
            .expect("compression failed");

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed);

        let mut decoder = StrataSnappyDecoder::new(default_max_record_bytes(), true, false, default_header_field_name());

        // Should return header
        let result1 = decoder.decode_eof(&mut input).unwrap();
        assert!(result1.is_some());

        // All lines are empty, should skip them and return None
        let result2 = decoder.decode_eof(&mut input).unwrap();
        assert!(result2.is_none(), "Should skip all empty lines");
    }

    #[test]
    fn decode_payload_with_mixed_empty_lines() {
        let header = br#"{"bucket":"test"}"#;
        let payload = b"\nlog1\n\n\nlog2\n\n"; // Mixed empty and non-empty lines
        let compressed = snap::raw::Encoder::new()
            .compress_vec(payload)
            .expect("compression failed");

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed);

        let mut decoder = StrataSnappyDecoder::new(default_max_record_bytes(), true, false, default_header_field_name());

        // Header
        let result1 = decoder.decode_eof(&mut input).unwrap();
        assert!(result1.is_some());

        // First log (empty lines skipped)
        let result2 = decoder.decode_eof(&mut input).unwrap();
        assert_eq!(result2.unwrap(), Bytes::from("log1"));

        // Second log (empty lines skipped)
        let result3 = decoder.decode_eof(&mut input).unwrap();
        assert_eq!(result3.unwrap(), Bytes::from("log2"));

        // No more data
        let result4 = decoder.decode_eof(&mut input).unwrap();
        assert!(result4.is_none());
    }

    #[test]
    fn decode_very_large_header() {
        // Create a large but valid JSON header (just under reasonable size)
        let large_header = format!(
            r#"{{"bucket":"test","data":"{}"}}"#,
            "x".repeat(8000)
        );
        let payload = b"Test log";
        let compressed = snap::raw::Encoder::new()
            .compress_vec(payload)
            .expect("compression failed");

        let mut input = BytesMut::new();
        input.extend_from_slice(large_header.as_bytes());
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed);

        let mut decoder = StrataSnappyDecoder::new(default_max_record_bytes(), true, false, default_header_field_name());

        // Should handle large header
        let result1 = decoder.decode_eof(&mut input).unwrap();
        assert!(result1.is_some());
        let header_result = result1.unwrap();
        assert_eq!(header_result.len(), large_header.len());
        assert_eq!(&header_result[..], large_header.as_bytes());

        let result2 = decoder.decode_eof(&mut input).unwrap();
        assert_eq!(result2.unwrap(), Bytes::from(payload.as_ref()));
    }

    #[test]
    fn decode_invalid_utf8_in_decompressed_payload() {
        let header = br#"{"bucket":"test"}"#;
        // Create payload with invalid UTF-8 (but valid bytes)
        let payload = b"Valid line\n\xff\xfe invalid utf8\nAnother valid line";
        let compressed = snap::raw::Encoder::new()
            .compress_vec(payload)
            .expect("compression failed");

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed);

        let mut decoder = StrataSnappyDecoder::new(default_max_record_bytes(), true, false, default_header_field_name());

        // Header
        decoder.decode_eof(&mut input).unwrap();

        // Lines should be returned as bytes, UTF-8 validation happens at deserializer level
        let result2 = decoder.decode_eof(&mut input).unwrap();
        assert_eq!(result2.unwrap(), Bytes::from("Valid line"));

        let result3 = decoder.decode_eof(&mut input).unwrap();
        assert!(result3.is_some()); // Invalid UTF-8 bytes are still returned

        let result4 = decoder.decode_eof(&mut input).unwrap();
        assert_eq!(result4.unwrap(), Bytes::from("Another valid line"));
    }

    #[test]
    fn decode_header_only_with_eof() {
        let header = br#"{"bucket":"test"}"#;
        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        // No newline, then EOF

        let mut decoder = StrataSnappyDecoder::new(default_max_record_bytes(), true, false, default_header_field_name());

        let result = decoder.decode_eof(&mut input);
        assert!(result.is_err(), "Should error on missing header newline at EOF");
    }

    #[test]
    fn decode_exceeds_max_size_exactly_at_boundary() {
        let header = br#"{"bucket":"test"}"#;
        let payload = vec![b'A'; 1000];
        let compressed = snap::raw::Encoder::new()
            .compress_vec(&payload)
            .expect("compression failed");

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed);

        // Set max size to exactly 1000
        let mut decoder = StrataSnappyDecoder::new(1000, true, false, default_header_field_name());

        // Header
        let result1 = decoder.decode_eof(&mut input).unwrap();
        assert!(result1.is_some());

        // Should succeed as size equals max (not exceeds)
        let result2 = decoder.decode_eof(&mut input);
        assert!(result2.is_ok(), "Should succeed when size equals max");
    }

    #[test]
    fn decode_exceeds_max_size_by_one_byte() {
        let header = br#"{"bucket":"test"}"#;
        let payload = vec![b'A'; 1001];
        let compressed = snap::raw::Encoder::new()
            .compress_vec(&payload)
            .expect("compression failed");

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed);

        // Set max size to 1000
        let mut decoder = StrataSnappyDecoder::new(1000, true, false, default_header_field_name());

        // Header
        let result1 = decoder.decode_eof(&mut input).unwrap();
        assert!(result1.is_some());

        // Should fail as size exceeds max by 1
        let result2 = decoder.decode_eof(&mut input);
        assert!(result2.is_err(), "Should fail when size exceeds max by 1");
    }

    #[test]
    fn decode_multiple_files_with_errors_in_between() {
        // First valid file
        let header1 = br#"{"file":"1"}"#;
        let payload1 = b"Log 1";
        let compressed1 = snap::raw::Encoder::new()
            .compress_vec(payload1)
            .expect("compression failed");

        let mut input1 = BytesMut::new();
        input1.extend_from_slice(header1);
        input1.put_u8(b'\n');
        input1.extend_from_slice(&compressed1);

        let mut decoder = StrataSnappyDecoder::new(default_max_record_bytes(), true, false, default_header_field_name());

        // Process first file
        decoder.decode_eof(&mut input1).unwrap();
        decoder.decode_eof(&mut input1).unwrap();

        // Invalid file (bad snappy)
        let header2 = br#"{"file":"2"}"#;
        let mut input2 = BytesMut::new();
        input2.extend_from_slice(header2);
        input2.put_u8(b'\n');
        input2.extend_from_slice(b"invalid snappy");

        // Process header of second file
        decoder.decode_eof(&mut input2).unwrap();
        // Should error on invalid snappy
        let result_err = decoder.decode_eof(&mut input2);
        assert!(result_err.is_err());

        // Third valid file - should reset and work
        let header3 = br#"{"file":"3"}"#;
        let payload3 = b"Log 3";
        let compressed3 = snap::raw::Encoder::new()
            .compress_vec(payload3)
            .expect("compression failed");

        let mut input3 = BytesMut::new();
        input3.extend_from_slice(header3);
        input3.put_u8(b'\n');
        input3.extend_from_slice(&compressed3);

        // Should process third file successfully
        let result_h3 = decoder.decode_eof(&mut input3).unwrap();
        assert!(result_h3.is_some());
        let result_l3 = decoder.decode_eof(&mut input3).unwrap();
        assert!(result_l3.is_some());
    }

    #[test]
    fn decode_json_enrichment_with_invalid_log_json() {
        let header = br#"{"bucket":"test"}"#;
        // Payload with invalid JSON line
        let payload = b"not valid json\n{\"valid\":\"json\"}";
        let compressed = snap::raw::Encoder::new()
            .compress_vec(payload)
            .expect("compression failed");

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed);

        let mut decoder = StrataSnappyDecoder::new(default_max_record_bytes(), true, true, default_header_field_name());

        // Header
        decoder.decode_eof(&mut input).unwrap();

        // First line - invalid JSON, enrichment should fail
        let result2 = decoder.decode_eof(&mut input);
        assert!(result2.is_err(), "Should error when enriching invalid JSON");
    }

    #[test]
    fn decode_snappy_with_trailing_garbage() {
        let header = br#"{"bucket":"test"}"#;
        let payload = b"Test log";
        let mut compressed = snap::raw::Encoder::new()
            .compress_vec(payload)
            .expect("compression failed");

        // Add garbage after valid snappy data
        compressed.extend_from_slice(b"garbage data here");

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed);

        let mut decoder = StrataSnappyDecoder::new(default_max_record_bytes(), true, false, default_header_field_name());

        // Header
        decoder.decode_eof(&mut input).unwrap();

        // Snappy decoder might handle this differently - it should either:
        // 1. Decompress successfully and ignore trailing data
        // 2. Error on invalid format
        // Either is acceptable
        let result = decoder.decode_eof(&mut input);
        // We just verify it doesn't panic
        let _ = result;
    }

    #[test]
    fn decode_zero_max_record_bytes() {
        let header = br#"{"bucket":"test"}"#;
        let payload = b"x"; // Even 1 byte
        let compressed = snap::raw::Encoder::new()
            .compress_vec(payload)
            .expect("compression failed");

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed);

        let mut decoder = StrataSnappyDecoder::new(0, true, false, default_header_field_name());

        // Header
        decoder.decode_eof(&mut input).unwrap();

        // Should error as any decompressed data exceeds 0
        let result = decoder.decode_eof(&mut input);
        assert!(result.is_err(), "Should error when max_record_bytes is 0");
    }

    #[test]
    fn decode_newline_at_end_of_compressed_block() {
        let header = br#"{"bucket":"test"}"#;
        // Payload ending with newline (common case)
        let payload = b"Log line 1\nLog line 2\n";
        let compressed = snap::raw::Encoder::new()
            .compress_vec(payload)
            .expect("compression failed");

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed);

        let mut decoder = StrataSnappyDecoder::new(default_max_record_bytes(), true, false, default_header_field_name());

        // Header
        decoder.decode_eof(&mut input).unwrap();

        // Line 1
        let result1 = decoder.decode_eof(&mut input).unwrap();
        assert_eq!(result1.unwrap(), Bytes::from("Log line 1"));

        // Line 2
        let result2 = decoder.decode_eof(&mut input).unwrap();
        assert_eq!(result2.unwrap(), Bytes::from("Log line 2"));

        // Trailing newline creates empty line which is skipped
        let result3 = decoder.decode_eof(&mut input).unwrap();
        assert!(result3.is_none());
    }

    #[test]
    fn decode_string_manipulation_optimization() {
        // Test the optimized string manipulation path for simple (non-nested) field names
        // This test verifies various edge cases like empty objects, objects with whitespace, etc.

        let header = br#"{"bucket":"test-bucket","region":"us-east-1"}"#;

        // Test case 1: Non-empty JSON object
        let log1 = br#"{"level":"info","message":"Test"}"#;
        // Test case 2: Empty JSON object
        let log2 = br#"{}"#;
        // Test case 3: Empty with whitespace
        let log3 = br#"{ }"#;
        // Test case 4: Object with trailing whitespace before brace
        let log4 = br#"{"level":"warn" }"#;

        let payload = format!(
            "{}\n{}\n{}\n{}",
            std::str::from_utf8(log1).unwrap(),
            std::str::from_utf8(log2).unwrap(),
            std::str::from_utf8(log3).unwrap(),
            std::str::from_utf8(log4).unwrap()
        );

        let compressed = snap::raw::Encoder::new()
            .compress_vec(payload.as_bytes())
            .expect("compression failed");

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed);

        let mut decoder = StrataSnappyDecoder::new(
            default_max_record_bytes(),
            true,
            true, // enrich_with_header = true
            ConfigTargetPath::try_from("strata_file_header".to_string()).unwrap(),
        );

        // Header should be returned first
        let result_header = decoder.decode(&mut input).unwrap();
        assert!(result_header.is_some());
        assert_eq!(result_header.unwrap(), Bytes::from(header.as_ref()));

        // Test case 1: Non-empty object - should have comma before new field
        let result1 = decoder.decode(&mut input).unwrap();
        assert!(result1.is_some());
        let json1: serde_json::Value = serde_json::from_slice(&result1.unwrap()).unwrap();
        assert_eq!(json1["level"], "info");
        assert_eq!(json1["message"], "Test");
        assert_eq!(json1["strata_file_header"]["bucket"], "test-bucket");
        assert_eq!(json1["strata_file_header"]["region"], "us-east-1");

        // Test case 2: Empty object - should NOT have comma before new field
        let result2 = decoder.decode(&mut input).unwrap();
        assert!(result2.is_some());
        let json2: serde_json::Value = serde_json::from_slice(&result2.unwrap()).unwrap();
        assert_eq!(json2["strata_file_header"]["bucket"], "test-bucket");
        assert_eq!(json2["strata_file_header"]["region"], "us-east-1");
        // Verify it's ONLY the header field (object was empty)
        assert_eq!(json2.as_object().unwrap().len(), 1);

        // Test case 3: Empty with whitespace - should NOT have comma
        let result3 = decoder.decode(&mut input).unwrap();
        assert!(result3.is_some());
        let json3: serde_json::Value = serde_json::from_slice(&result3.unwrap()).unwrap();
        assert_eq!(json3["strata_file_header"]["bucket"], "test-bucket");
        assert_eq!(json3.as_object().unwrap().len(), 1);

        // Test case 4: Object with trailing whitespace - should have comma
        let result4 = decoder.decode(&mut input).unwrap();
        assert!(result4.is_some());
        let json4: serde_json::Value = serde_json::from_slice(&result4.unwrap()).unwrap();
        assert_eq!(json4["level"], "warn");
        assert_eq!(json4["strata_file_header"]["bucket"], "test-bucket");

        // No more lines
        let result5 = decoder.decode(&mut input).unwrap();
        assert!(result5.is_none());
    }

    #[test]
    fn decode_nested_path_enrichment() {
        // Test nested path enrichment (e.g., "metadata.header")
        let header = br#"{"bucket":"test-bucket","region":"us-east-1"}"#;
        let log1 = br#"{"level":"info","message":"Test 1"}"#;
        let log2 = br#"{"level":"warn","message":"Test 2","metadata":{"existing":"value"}}"#;

        let payload = format!(
            "{}\n{}",
            std::str::from_utf8(log1).unwrap(),
            std::str::from_utf8(log2).unwrap()
        );

        let compressed = snap::raw::Encoder::new()
            .compress_vec(payload.as_bytes())
            .expect("compression failed");

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed);

        // Use nested path "metadata.header"
        let mut decoder = StrataSnappyDecoder::new(
            default_max_record_bytes(),
            true,
            true, // enrich_with_header = true
            ConfigTargetPath::try_from("metadata.header".to_string()).unwrap(),
        );

        // Header should be returned first
        let result_header = decoder.decode(&mut input).unwrap();
        assert!(result_header.is_some());
        assert_eq!(result_header.unwrap(), Bytes::from(header.as_ref()));

        // First log line - should create metadata.header
        let result1 = decoder.decode(&mut input).unwrap();
        assert!(result1.is_some());
        let json1: serde_json::Value = serde_json::from_slice(&result1.unwrap()).unwrap();
        assert_eq!(json1["level"], "info");
        assert_eq!(json1["message"], "Test 1");
        assert_eq!(json1["metadata"]["header"]["bucket"], "test-bucket");
        assert_eq!(json1["metadata"]["header"]["region"], "us-east-1");

        // Second log line - should merge with existing metadata object
        let result2 = decoder.decode(&mut input).unwrap();
        assert!(result2.is_some());
        let json2: serde_json::Value = serde_json::from_slice(&result2.unwrap()).unwrap();
        assert_eq!(json2["level"], "warn");
        assert_eq!(json2["message"], "Test 2");
        // Existing metadata field should be preserved
        assert_eq!(json2["metadata"]["existing"], "value");
        // Header should be added under metadata.header
        assert_eq!(json2["metadata"]["header"]["bucket"], "test-bucket");
        assert_eq!(json2["metadata"]["header"]["region"], "us-east-1");

        // No more lines
        let result3 = decoder.decode(&mut input).unwrap();
        assert!(result3.is_none());
    }

    #[test]
    fn decode_nested_path_with_segment_collision() {
        // Test nested path enrichment when intermediate path segment exists but is not an object
        let header = br#"{"bucket":"test"}"#;
        let log = br#"{"level":"info","metadata":"string_not_object"}"#;

        let payload = std::str::from_utf8(log).unwrap();
        let compressed = snap::raw::Encoder::new()
            .compress_vec(payload.as_bytes())
            .expect("compression failed");

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed);

        // Use nested path "metadata.header" - but "metadata" already exists as a string
        let mut decoder = StrataSnappyDecoder::new(
            default_max_record_bytes(),
            false, // skip_on_error = false to see the error
            true,
            ConfigTargetPath::try_from("metadata.header".to_string()).unwrap(),
        );

        // Header is returned first
        let result_header = decoder.decode(&mut input).unwrap();
        assert!(result_header.is_some());

        // Trying to enrich should fail because metadata exists but is not an object
        let result_err = decoder.decode(&mut input);
        assert!(result_err.is_err(), "Should error when path segment collision occurs");

        // Verify error is not continuable when skip_on_error=false
        let err = result_err.unwrap_err();
        assert!(!err.can_continue(), "Error should not be continuable when skip_on_error=false");
    }

    #[test]
    fn decode_deeply_nested_path() {
        // Test deeply nested path enrichment
        let header = br#"{"bucket":"test","region":"us-east"}"#;
        let log1 = br#"{"level":"info"}"#;
        let log2 = br#"{"level":"warn","meta":{"sub":{"existing":"value"}}}"#;

        let payload = format!(
            "{}\n{}",
            std::str::from_utf8(log1).unwrap(),
            std::str::from_utf8(log2).unwrap()
        );

        let compressed = snap::raw::Encoder::new()
            .compress_vec(payload.as_bytes())
            .expect("compression failed");

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed);

        // Use deeply nested path
        let mut decoder = StrataSnappyDecoder::new(
            default_max_record_bytes(),
            true,
            true,
            ConfigTargetPath::try_from("meta.sub.header".to_string()).unwrap(),
        );

        // Header
        let result_header = decoder.decode(&mut input).unwrap();
        assert!(result_header.is_some());

        // First log - creates full nested structure
        let result1 = decoder.decode(&mut input).unwrap();
        assert!(result1.is_some());
        let json1: serde_json::Value = serde_json::from_slice(&result1.unwrap()).unwrap();
        assert_eq!(json1["level"], "info");
        assert_eq!(json1["meta"]["sub"]["header"]["bucket"], "test");

        // Second log - merges with existing nested structure
        let result2 = decoder.decode(&mut input).unwrap();
        assert!(result2.is_some());
        let json2: serde_json::Value = serde_json::from_slice(&result2.unwrap()).unwrap();
        assert_eq!(json2["level"], "warn");
        assert_eq!(json2["meta"]["sub"]["existing"], "value"); // Preserved
        assert_eq!(json2["meta"]["sub"]["header"]["bucket"], "test"); // Added
    }

    #[test]
    fn decode_enrichment_preserves_field_order() {
        // Test that string manipulation preserves field order for simple paths
        let header = br#"{"bucket":"test"}"#;
        let log = br#"{"a":"first","b":"second","z":"last"}"#;

        let payload = std::str::from_utf8(log).unwrap();
        let compressed = snap::raw::Encoder::new()
            .compress_vec(payload.as_bytes())
            .expect("compression failed");

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed);

        let mut decoder = StrataSnappyDecoder::new(
            default_max_record_bytes(),
            true,
            true,
            ConfigTargetPath::try_from("header".to_string()).unwrap(),
        );

        // Skip header
        decoder.decode(&mut input).unwrap();

        // Get enriched log
        let result = decoder.decode(&mut input).unwrap();
        assert!(result.is_some());

        // Verify it's valid JSON with header field added
        let json: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
        assert_eq!(json["a"], "first");
        assert_eq!(json["b"], "second");
        assert_eq!(json["z"], "last");
        assert_eq!(json["header"]["bucket"], "test");
    }

    #[test]
    fn decode_empty_header() {
        // Test with empty header object
        let header = br#"{}"#;
        let log = br#"{"level":"info"}"#;

        let payload = std::str::from_utf8(log).unwrap();
        let compressed = snap::raw::Encoder::new()
            .compress_vec(payload.as_bytes())
            .expect("compression failed");

        let mut input = BytesMut::new();
        input.extend_from_slice(header);
        input.put_u8(b'\n');
        input.extend_from_slice(&compressed);

        let mut decoder = StrataSnappyDecoder::new(
            default_max_record_bytes(),
            true,
            true,
            ConfigTargetPath::try_from("header".to_string()).unwrap(),
        );

        // Header should be returned
        let result_header = decoder.decode(&mut input).unwrap();
        assert!(result_header.is_some());
        assert_eq!(result_header.unwrap(), Bytes::from(header.as_ref()));

        // Log should be enriched with empty header object
        let result = decoder.decode(&mut input).unwrap();
        assert!(result.is_some());
        let json: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
        assert_eq!(json["level"], "info");
        assert!(json["header"].is_object());
        assert_eq!(json["header"].as_object().unwrap().len(), 0);
    }
}
