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

use crate::errors::ParseError;
use core::{
    fmt,
    ops::Deref,
    str::{self, FromStr},
};

/// Maximum size of an identifier.
const MAX_LENGTH: usize = 32;

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
pub struct Ident {
    /// Byte array containing an ASCII-encoded string.
    bytes: [u8; MAX_LENGTH],

    /// Length of the string in ASCII characters (i.e. bytes).
    length: u8,
}

impl Ident {
    /// Maximum length of an [`Ident`] - 32 ASCII characters (i.e. 32-bytes).
    ///
    /// This value corresponds to the maximum size of a function symbolic names
    /// and parameter names according to the PHC string format.
    pub const fn max_len() -> usize {
        MAX_LENGTH
    }

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
    /// For fallible non-panicking parsing of an [`Ident`], use the [`FromStr`]
    /// impl on this type instead, e.g. `s.parse::<Ident>()`.
    pub const fn new(s: &str) -> Self {
        let input = s.as_bytes();

        /// Constant panicking assertion.
        // TODO(tarcieri): use const panic when stable.
        // See: https://github.com/rust-lang/rust/issues/51999
        macro_rules! const_assert {
            ($bool:expr, $msg:expr) => {
                [$msg][!$bool as usize]
            };
        }

        const_assert!(!input.is_empty(), "PHC string ident can't be empty");
        const_assert!(input.len() <= MAX_LENGTH, "PHC string ident too long");

        // TODO(tarcieri): use `const_mut_ref` when stable.
        // See: <https://github.com/rust-lang/rust/issues/57349>
        macro_rules! validate_and_extract_byte {
            ($($pos:expr),+) => {{
                [$(
                    if $pos < input.len() {
                        let byte = input[$pos];

                        const_assert!(
                            matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'),
                            "invalid character in PHC string ident"
                        );

                        byte
                    } else {
                        0u8
                    },
                )+]
             }};
        }

        #[rustfmt::skip]
        let bytes = validate_and_extract_byte![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
        ];

        Self {
            bytes,
            length: input.len() as u8,
        }
    }
}

impl AsRef<str> for Ident {
    fn as_ref(&self) -> &str {
        str::from_utf8(&self.bytes[..(self.length as usize)]).expect("malformed PHC ident")
    }
}

impl Deref for Ident {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_ref()
    }
}

impl FromStr for Ident {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        let input = s.as_bytes();

        if input.is_empty() {
            return Err(ParseError::default());
        }

        let mut bytes = [0u8; MAX_LENGTH];
        let output = bytes.get_mut(..input.len());

        for &char in input {
            if !matches!(char, b'a'..=b'z' | b'0'..=b'9' | b'-') {
                return Err(ParseError {
                    invalid_char: Some(char.into()),
                    too_long: output.is_none(),
                });
            }
        }

        match output {
            Some(out) => out.copy_from_slice(input),
            None => return Err(ParseError::too_long()),
        }

        Ok(Self {
            bytes,
            length: input.len() as u8,
        })
    }
}

impl fmt::Display for Ident {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&*self)
    }
}

impl fmt::Debug for Ident {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Ident").field(&self.as_ref()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::Ident;

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
            let from_str_val = example.parse::<Ident>().unwrap();
            assert_eq!(example, &*const_val);
            assert_eq!(example, &*from_str_val);
        }
    }

    #[test]
    #[should_panic]
    fn reject_empty_const() {
        Ident::new(INVALID_EMPTY);
    }

    #[test]
    fn reject_empty_fallible() {
        let err = INVALID_EMPTY.parse::<Ident>().err().unwrap();
        assert_eq!(err.invalid_char, None);
        assert!(!err.too_long);
    }

    #[test]
    #[should_panic]
    fn reject_invalid_char_const() {
        Ident::new(INVALID_CHAR);
    }

    #[test]
    fn reject_invalid_char_fallible() {
        let err = INVALID_CHAR.parse::<Ident>().err().unwrap();
        assert_eq!(err.invalid_char, Some(';'));
        assert!(!err.too_long);
    }

    #[test]
    #[should_panic]
    fn reject_too_long_const() {
        Ident::new(INVALID_TOO_LONG);
    }

    #[test]
    fn reject_too_long_fallible() {
        let err = INVALID_TOO_LONG.parse::<Ident>().err().unwrap();
        assert_eq!(err.invalid_char, None);
        assert!(err.too_long);
    }

    #[test]
    #[should_panic]
    fn reject_invalid_char_and_too_long_const() {
        Ident::new(INVALID_CHAR_AND_TOO_LONG);
    }

    #[test]
    fn reject_invalid_char_and_too_long_fallible() {
        let err = INVALID_CHAR_AND_TOO_LONG.parse::<Ident>().err().unwrap();
        assert_eq!(err.invalid_char, Some('!'));
        assert!(err.too_long);
    }
}
