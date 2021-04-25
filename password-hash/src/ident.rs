//! Algorithm or parameter identifier.
//!
//! Implements the following parts of the [PHC string format specification][1]:
//!
//! > The function symbolic name is a sequence of characters in: `[a-z0-9-]`
//! > (lowercase letters, digits, and the minus sign). No other character is
//! > allowed. Each function defines its own identifier (or identifiers in case
//! > of a function family); identifiers should be explicit (human readable,
//! > not a single digit), with a length of about 5 to 10 characters. An
//! > identifier name MUST NOT exceed 32 characters in length.
//! >
//! > Each parameter name shall be a sequence of characters in: `[a-z0-9-]`
//! > (lowercase letters, digits, and the minus sign). No other character is
//! > allowed. Parameter names SHOULD be readable for a human user. A
//! > parameter name MUST NOT exceed 32 characters in length.
//!
//! [1]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md

use crate::{Error, Result};
use core::{convert::TryFrom, fmt, ops::Deref, str};

/// Algorithm or parameter identifier.
///
/// This type encompasses both the "function symbolic name" and "parameter name"
/// use cases as described in the [PHC string format specification][1].
///
/// # Constraints
/// - ASCII-encoded string consisting of the characters `[a-z0-9-]`
///   (lowercase letters, digits, and the minus sign)
/// - Minimum length: 1 ASCII character (i.e. 1-byte)
/// - Maximum length: 32 ASCII characters (i.e. 32-bytes)
///
/// [1]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
#[derive(Copy, Clone, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Ident<'a>(&'a str);

impl<'a> Ident<'a> {
    /// Maximum length of an [`Ident`] - 32 ASCII characters (i.e. 32-bytes).
    ///
    /// This value corresponds to the maximum size of a function symbolic names
    /// and parameter names according to the PHC string format.
    /// Maximum length of an [`Ident`] - 32 ASCII characters (i.e. 32-bytes).
    ///
    /// This value corresponds to the maximum size of a function symbolic names
    /// and parameter names according to the PHC string format.
    const MAX_LENGTH: usize = 32;

    /// Parse an [`Ident`] from a string.
    ///
    /// # Panics
    ///
    /// Must conform to the contraints given in the type-level documentation,
    /// or else it will panic.
    ///
    /// This method is intended for use in a `const` context where instead of
    /// panicking it will cause a compile error.
    ///
    /// For fallible non-panicking parsing of an [`Ident`], use the [`TryFrom`]
    /// impl on this type instead.
    pub const fn new(s: &'a str) -> Self {
        let input = s.as_bytes();

        /// Constant panicking assertion.
        // TODO(tarcieri): use const panic when stable.
        // See: https://github.com/rust-lang/rust/issues/51999
        macro_rules! const_assert {
            ($bool:expr, $msg:expr) => {
                [$msg][!$bool as usize]
            };
        }

        const_assert!(!input.is_empty(), "PHC ident string can't be empty");
        const_assert!(input.len() <= Self::MAX_LENGTH, "PHC ident string too long");

        macro_rules! validate_chars {
            ($($pos:expr),+) => {
                $(
                    if $pos < input.len() {
                        const_assert!(
                            is_char_valid(input[$pos]),
                            "invalid character in PHC string ident"
                        );
                    }
                )+
            };
        }

        validate_chars!(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31
        );

        Self(s)
    }

    /// Borrow this ident as a `str`
    pub fn as_str(&self) -> &'a str {
        self.0
    }
}

impl<'a> AsRef<str> for Ident<'a> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<'a> Deref for Ident<'a> {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

// Note: this uses `TryFrom` instead of `FromStr` to support a lifetime on
// the `str` the value is being parsed from.
impl<'a> TryFrom<&'a str> for Ident<'a> {
    type Error = Error;

    fn try_from(s: &'a str) -> Result<Self> {
        if s.is_empty() {
            return Err(Error::ParamNameInvalid);
        }

        let bytes = s.as_bytes();
        let too_long = bytes.len() > Self::MAX_LENGTH;

        for &c in bytes {
            if !is_char_valid(c) {
                return Err(Error::ParamNameInvalid);
            }
        }

        if too_long {
            return Err(Error::ParamNameInvalid);
        }

        Ok(Self::new(s))
    }
}

impl<'a> fmt::Display for Ident<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&*self)
    }
}

impl<'a> fmt::Debug for Ident<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Ident").field(&self.as_ref()).finish()
    }
}

/// Ensure the given ASCII character (i.e. byte) is allowed in an [`Ident`].
const fn is_char_valid(c: u8) -> bool {
    matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'-')
}

#[cfg(test)]
mod tests {
    use super::{Error, Ident};
    use core::convert::TryFrom;

    // Invalid ident examples
    const INVALID_EMPTY: &str = "";
    const INVALID_CHAR: &str = "argon2;d";
    const INVALID_TOO_LONG: &str = "012345678911234567892123456789312";
    const INVALID_CHAR_AND_TOO_LONG: &str = "0!2345678911234567892123456789312";

    #[test]
    fn parse_valid() {
        let valid_examples = ["6", "x", "argon2d", "01234567891123456789212345678931"];

        for &example in &valid_examples {
            let const_val = Ident::new(example);
            let try_from_val = Ident::try_from(example).unwrap();
            assert_eq!(example, &*const_val);
            assert_eq!(example, &*try_from_val);
        }
    }

    #[test]
    #[should_panic]
    fn reject_empty_const() {
        Ident::new(INVALID_EMPTY);
    }

    #[test]
    fn reject_empty_fallible() {
        let err = Ident::try_from(INVALID_EMPTY).err().unwrap();
        assert_eq!(err, Error::ParamNameInvalid);
    }

    #[test]
    #[should_panic]
    fn reject_invalid_char_const() {
        Ident::new(INVALID_CHAR);
    }

    #[test]
    fn reject_invalid_char_fallible() {
        let err = Ident::try_from(INVALID_CHAR).err().unwrap();
        assert_eq!(err, Error::ParamNameInvalid);
    }

    #[test]
    #[should_panic]
    fn reject_too_long_const() {
        Ident::new(INVALID_TOO_LONG);
    }

    #[test]
    fn reject_too_long_fallible() {
        let err = Ident::try_from(INVALID_TOO_LONG).err().unwrap();
        assert_eq!(err, Error::ParamNameInvalid);
    }

    #[test]
    #[should_panic]
    fn reject_invalid_char_and_too_long_const() {
        Ident::new(INVALID_CHAR_AND_TOO_LONG);
    }

    #[test]
    fn reject_invalid_char_and_too_long_fallible() {
        let err = Ident::try_from(INVALID_CHAR_AND_TOO_LONG).err().unwrap();
        assert_eq!(err, Error::ParamNameInvalid);
    }
}
