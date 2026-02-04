//! Configuration for frame encapsulation.

use vector_config::configurable_component;

/// Configuration for character-delimited framing.
#[configurable_component]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EncapFramingConfig {
    /// Constant byte sequence framing.
    Const(ConstFrameEncap),
}

/// Configuration for constant byte sequence framing.
#[configurable_component]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConstFrameEncap {
    /// Frame prefix bytes.
    #[serde(with = "hex::serde")]
    pub prefix: Vec<u8>,

    /// Frame suffix bytes.
    #[serde(with = "hex::serde")]
    pub suffix: Vec<u8>,
}
