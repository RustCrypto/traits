//! Hexadecimal encoding helpers

use crate::{Error, Result};
use core::{fmt, str};

/// Write the provided slice to the formatter as lower case hexadecimal
#[inline]
pub(crate) fn write_lower(slice: &[u8], formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in slice {
        write!(formatter, "{:02x}", byte)?;
    }
    Ok(())
}

/// Write the provided slice to the formatter as upper case hexadecimal
#[inline]
pub(crate) fn write_upper(slice: &[u8], formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in slice {
        write!(formatter, "{:02X}", byte)?;
    }
    Ok(())
}

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
    use core::fmt;
    use hex_literal::hex;

    const EXAMPLE_DATA: &[u8] = &hex!("0123456789ABCDEF");
    const EXAMPLE_HEX_LOWER: &str = "0123456789abcdef";
    const EXAMPLE_HEX_UPPER: &str = "0123456789ABCDEF";

    struct Wrapper<'a>(&'a [u8]);

    impl fmt::LowerHex for Wrapper<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            super::write_lower(self.0, f)
        }
    }

    impl fmt::UpperHex for Wrapper<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            super::write_upper(self.0, f)
        }
    }

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

    #[test]
    fn encode_lower() {
        assert_eq!(format!("{:x}", Wrapper(EXAMPLE_DATA)), EXAMPLE_HEX_LOWER);
    }

    #[test]
    fn encode_upper() {
        assert_eq!(format!("{:X}", Wrapper(EXAMPLE_DATA)), EXAMPLE_HEX_UPPER);
    }
}
