//! Hexadecimal encoding helpers

use crate::{Error, Result};
use core::str;

/// Decode the provided hexadecimal string into the provided buffer.
///
/// Accepts either lower case or upper case hexadecimal.
pub(crate) fn decode(hex: &str, out: &mut [u8]) -> Result<()> {
    if base16ct::mixed::decode(hex, out)?.len() == out.len() {
        Ok(())
    } else {
        Err(Error)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use hex_literal::hex;

    const EXAMPLE_DATA: &[u8] = &hex!("0123456789ABCDEF");
    const EXAMPLE_HEX_LOWER: &str = "0123456789abcdef";

    #[test]
    fn decode_lower() {
        let mut buf = [0u8; 8];
        super::decode(EXAMPLE_HEX_LOWER, &mut buf).unwrap();
        assert_eq!(buf, EXAMPLE_DATA);
    }

    #[test]
    fn decode_upper() {
        let mut buf = [0u8; 8];
        super::decode(EXAMPLE_HEX_LOWER, &mut buf).unwrap();
        assert_eq!(buf, EXAMPLE_DATA);
    }

    #[test]
    fn decode_rejects_too_short() {
        let mut buf = [0u8; 9];
        assert!(super::decode(EXAMPLE_HEX_LOWER, &mut buf).is_err());
    }

    #[test]
    fn decode_rejects_too_long() {
        let mut buf = [0u8; 7];
        assert!(super::decode(EXAMPLE_HEX_LOWER, &mut buf).is_err());
    }
}
