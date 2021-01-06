//! Salt string support.

use crate::{
    errors::{B64Error, ParseError},
    params::ValueStr,
};
use core::{
    convert::{TryFrom, TryInto},
    fmt, str,
};

/// Salt string.
///
/// In password hashing, a "salt" is an additional value used to
/// personalize/tweak the output of a password hashing function for a given
/// input password.
///
/// Salts help defend against attacks based on precomputed tables of hashed
/// passwords, i.e. "[rainbow tables][1]".
///
/// The [`Salt`] type implements the RECOMMENDED best practices for salts
/// described in the [PHC string format specification][2], namely:
///
/// > - Maximum lengths for salt, output and parameter values are meant to help
/// >   consumer implementations, in particular written in C and using
/// >   stack-allocated buffers. These buffers must account for the worst case,
/// >   i.e. the maximum defined length. Therefore, keep these lengths low.
/// > - The role of salts is to achieve uniqueness. A random salt is fine for
/// >   that as long as its length is sufficient; a 16-byte salt would work well
/// >   (by definition, UUID are very good salts, and they encode over exactly
/// >   16 bytes). 16 bytes encode as 22 characters in B64. Functions should
/// >   disallow salt values that are too small for security (4 bytes should be
/// >   viewed as an absolute minimum).
///
/// # Recommended length
/// The recommended default length for a salt string is **16-bytes** (128-bits).
///
/// See below for rationale.
///
/// # Constraints
/// Salt strings are constrained to the following set of characters per the
/// PHC spec:
///
/// > The salt consists in a sequence of characters in: `[a-zA-Z0-9/+.-]`
/// > (lowercase letters, uppercase letters, digits, /, +, . and -).
///
/// Additionally the following length restrictions are enforced based on the
/// guidelines from the spec:
///
/// - Minimum length: **4**-bytes
/// - Maximum length: **48**-bytes
///
/// A maximum length is enforced based on the above recommendation for
/// supporting stack-allocated buffers (which this library uses), and the
/// specific determination of 48-bytes is taken as a best practice from the
/// [Argon2 Encoding][3] specification in the same document:
///
/// > The length in bytes of the salt is between 8 and 48 bytes<sup>†</sup>, thus
/// > yielding a length in characters between 11 and 64 characters (and that
/// > length is never equal to 1 modulo 4). The default byte length of the salt
/// > is 16 bytes (22 characters in B64 encoding). An encoded UUID, or a
/// > sequence of 16 bytes produced with a cryptographically strong PRNG, are
/// > appropriate salt values.
/// >
/// > <sup>†</sup>The Argon2 specification states that the salt can be much longer, up
/// > to 2^32-1 bytes, but this makes little sense for password hashing.
/// > Specifying a relatively small maximum length allows for parsing with a
/// > stack allocated buffer.)
///
/// Based on this guidance, this type enforces an upper bound of 48-bytes
/// as a reasonable maximum, and recommends using 16-bytes.
///
/// [1]: https://en.wikipedia.org/wiki/Rainbow_table
/// [2]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#function-duties
/// [3]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#argon2-encoding
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Salt<'a>(ValueStr<'a>);

impl<'a> Salt<'a> {
    /// Minimum length of a [`Salt`] string: 2-bytes.
    ///
    /// NOTE: this is below the recommended
    // TODO(tarcieri): support shorter salts for MCF?
    pub const fn min_len() -> usize {
        4
    }

    /// Maximum length of a [`Salt`] string: 48-bytes.
    ///
    /// See type-level documentation about [`Salt`] for more information.
    pub const fn max_len() -> usize {
        ValueStr::max_len()
    }

    /// Recommended length of a salt: 16-bytes.
    pub const fn recommended_len() -> usize {
        16
    }

    /// Create a [`Salt`] from the given `str`, validating it according to
    /// [`Salt::min_len`] and [`Salt::max_len`] length restrictions.
    pub fn new(input: &'a str) -> Result<Self, ParseError> {
        // TODO(tarcieri): support shorter salts for MCF?
        if input.len() < Self::min_len() {
            return Err(ParseError::TooShort);
        }

        if input.len() > Self::max_len() {
            return Err(ParseError::TooLong);
        }

        Ok(Self(input.try_into()?))
    }

    /// Attempt to decode a [`b64`][`crate::b64`]-encoded [`Salt`], writing the
    /// decoded result into the provided buffer, and returning a slice of the
    /// buffer containing the decoded result on success.
    ///
    /// [1]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#argon2-encoding
    pub fn b64_decode<'b>(&self, buf: &'b mut [u8]) -> Result<&'b [u8], B64Error> {
        self.0.b64_decode(buf)
    }

    /// Borrow this value as a `str`.
    pub fn as_str(&self) -> &'a str {
        self.0.as_str()
    }

    /// Borrow this value as bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.as_str().as_bytes()
    }

    /// Get the length of this value in ASCII characters.
    pub fn len(&self) -> usize {
        self.as_str().len()
    }
}

impl<'a> AsRef<str> for Salt<'a> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<'a> TryFrom<&'a str> for Salt<'a> {
    type Error = ParseError;

    fn try_from(input: &'a str) -> Result<Self, ParseError> {
        Self::new(input)
    }
}

impl<'a> fmt::Display for Salt<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'a> fmt::Debug for Salt<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Salt({:?})", self.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::{ParseError, Salt};

    #[test]
    fn new_with_valid_min_length_input() {
        let s = "abcd";
        let salt = Salt::new(s).unwrap();
        assert_eq!(salt.as_ref(), s);
    }

    #[test]
    fn new_with_valid_max_length_input() {
        let s = "012345678911234567892123456789312345678941234567";
        let salt = Salt::new(s).unwrap();
        assert_eq!(salt.as_ref(), s);
    }

    #[test]
    fn reject_new_too_short() {
        for &too_short in &["", "a", "ab", "abc"] {
            let err = Salt::new(too_short).err().unwrap();
            assert_eq!(err, ParseError::TooShort);
        }
    }

    #[test]
    fn reject_new_too_long() {
        let s = "0123456789112345678921234567893123456789412345678";
        let err = Salt::new(s).err().unwrap();
        assert_eq!(err, ParseError::TooLong);
    }
}
