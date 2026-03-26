//! Configuration for frame encapsulation.

use bytes::BytesMut;
use tokio_util::codec::Encoder;
use vector_config::configurable_component;

use crate::encoding::BoxedFramingError;

/// Configuration for character-delimited framing.
#[configurable_component]
#[derive(Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EncapFramingConfig {
    /// Constant byte sequence framing.
    Const(ConstFrameEncap),
}

/// Batch encapsulation framer.
#[derive(Debug, Clone)]
pub enum EncapFramer {
    /// Constant byte sequence framing.
    Const(ConstFrameEncoder),
}

impl EncapFramingConfig {
    /// Build `EncapFramer` from config.
    pub fn build(&self) -> Result<EncapFramer, vector_common::Error> {
        match self {
            EncapFramingConfig::Const(config) => Ok(EncapFramer::Const(config.build())),
        }
    }
}

impl Encoder<()> for EncapFramer {
    type Error = BoxedFramingError;
    fn encode(&mut self, _: (), buffer: &mut BytesMut) -> Result<(), BoxedFramingError> {
        match self {
            EncapFramer::Const(encoder) => encoder.encode((), buffer),
        }
    }
}

/// Configuration for constant byte sequence framing.
#[configurable_component]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConstFrameEncap {
    /// Frame prefix bytes.
    #[serde(with = "hex::serde", default = "default_frame_marker_bytes")]
    pub prefix: Vec<u8>,

    /// Frame suffix bytes.
    #[serde(with = "hex::serde", default = "default_frame_marker_bytes")]
    pub suffix: Vec<u8>,
}

fn default_frame_marker_bytes() -> Vec<u8> {
    Vec::new()
}

impl ConstFrameEncap {
    /// Build `ConstFrameEncoder` from config.
    pub fn build(&self) -> ConstFrameEncoder {
        ConstFrameEncoder {
            prefix: self.prefix.clone(),
            suffix: self.suffix.clone(),
        }
    }
}

/// An encoder to apply constant header / footer framing
#[derive(Debug, Clone)]
pub struct ConstFrameEncoder {
    prefix: Vec<u8>,
    suffix: Vec<u8>,
}

impl ConstFrameEncoder {
    /// Create a new `ConstFrameEncoder` with the given prefix and suffix.
    pub fn new(prefix: Vec<u8>, suffix: Vec<u8>) -> Self {
        Self { prefix, suffix }
    }
}

impl Encoder<()> for ConstFrameEncoder {
    type Error = BoxedFramingError;

    fn encode(&mut self, _: (), buffer: &mut BytesMut) -> Result<(), BoxedFramingError> {
        let data = buffer.split();
        buffer.extend_from_slice(&self.prefix);
        buffer.extend_from_slice(&data);
        buffer.extend_from_slice(&self.suffix);
        Ok(())
    }
}
