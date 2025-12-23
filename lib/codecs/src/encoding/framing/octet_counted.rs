use bytes::BytesMut;
use tokio_util::codec::Encoder;
use core::fmt::Write;

use super::BoxedFramingError;

/// Encoder that frames byte sequences using octet-counted framing.
#[derive(Debug, Clone)]
pub struct OctetCountedEncoder {}

impl Encoder<()> for OctetCountedEncoder {
    type Error = BoxedFramingError;

    fn encode(&mut self, _: (), buf: &mut BytesMut) -> Result<(), BoxedFramingError> {
        let data = buf.split().freeze();
        let len = data.len() as usize;
        if len > 0 {
            write!(buf, "{} ", len).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            buf.extend_from_slice(&data[..]);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode() {
        let mut encoder = OctetCountedEncoder{};

        let mut buffer = BytesMut::from("abc");
        encoder.encode((), &mut buffer).unwrap();

        assert_eq!(b"3 abc", &buffer[..]);
    }
}
