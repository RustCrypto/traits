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

use super::StringBuf;
use crate::{Error, Result};
use core::{
    fmt,
    ops::Deref,
    str::{self, FromStr},
};

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
pub struct Ident(StringBuf<{ Ident::MAX_LENGTH }>);

impl Ident {
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
    /// String must conform to the constraints given in the type-level
    /// documentation.
    pub const fn new(s: &str) -> Result<Self> {
        let input = s.as_bytes();

        match input.len() {
            1..=Self::MAX_LENGTH => {
                let mut i = 0;

                while i < input.len() {
                    if !matches!(input[i], b'a'..=b'z' | b'0'..=b'9' | b'-') {
                        return Err(Error::ParamNameInvalid);
                    }

                    i += 1;
                }

                match StringBuf::new(s) {
                    Ok(buf) => Ok(Self(buf)),
                    Err(e) => Err(e),
                }
            }
            _ => Err(Error::ParamNameInvalid),
        }
    }

    /// Parse an [`Ident`] from a string, panicking on parse errors.
    ///
    /// This function exists as a workaround for `unwrap` not yet being
    /// stable in `const fn` contexts, and is intended to allow the result to
    /// be bound to a constant value.
    pub const fn new_unwrap(s: &str) -> Self {
        assert!(!s.is_empty(), "PHC ident string can't be empty");
        assert!(s.len() <= Self::MAX_LENGTH, "PHC ident string too long");

        match Self::new(s) {
            Ok(ident) => ident,
            Err(_) => panic!("invalid PHC string format identifier"),
        }
    }

    /// Borrow this ident as a `str`
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Ident {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for Ident {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for Ident {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

impl TryFrom<&str> for Ident {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

impl fmt::Display for Ident {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self)
    }
}

impl fmt::Debug for Ident {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Ident").field(&self.as_ref()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, Ident};

    // Invalid ident examples
    const INVALID_EMPTY: &str = "";
    const INVALID_CHAR: &str = "argon2;d";
    const INVALID_TOO_LONG: &str = "012345678911234567892123456789312";
    const INVALID_CHAR_AND_TOO_LONG: &str = "0!2345678911234567892123456789312";

    #[test]
    fn parse_valid() {
        let valid_examples = ["6", "x", "argon2d", "01234567891123456789212345678931"];

        for &example in &valid_examples {
            assert_eq!(example, &*Ident::new(example).unwrap());
        }
    }

    #[test]
    fn reject_empty() {
        assert_eq!(Ident::new(INVALID_EMPTY), Err(Error::ParamNameInvalid));
    }

    #[test]
    fn reject_invalid() {
        assert_eq!(Ident::new(INVALID_CHAR), Err(Error::ParamNameInvalid));
    }

    #[test]
    fn reject_too_long() {
        assert_eq!(Ident::new(INVALID_TOO_LONG), Err(Error::ParamNameInvalid));
    }

    #[test]
    fn reject_invalid_char_and_too_long() {
        assert_eq!(
            Ident::new(INVALID_CHAR_AND_TOO_LONG),
            Err(Error::ParamNameInvalid)
        );
    }
}
