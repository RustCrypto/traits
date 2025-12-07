//! Salt string support.

use super::StringBuf;
use crate::{Error, Result, errors::InvalidValue};
use base64ct::{Base64Unpadded as B64, Encoding};
use core::{
    fmt,
    ops::Deref,
    str::{self, FromStr},
};
#[cfg(feature = "rand_core")]
use rand_core::{CryptoRng, TryCryptoRng};

/// Error message used with `expect` for when internal invariants are violated
/// (i.e. the contents of a [`Salt`] should always be valid)
const INVARIANT_VIOLATED_MSG: &str = "salt string invariant violated";

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
/// See [`Salt::RECOMMENDED_LENGTH`] for more information.
///
/// # Constraints
/// Salt strings are constrained to the following set of characters per the
/// PHC spec:
///
/// > The salt consists in a sequence of characters in: `[a-zA-Z0-9/+.-]`
/// > (lowercase letters, uppercase letters, digits, `/`, `+`, `.` and `-`).
///
/// Additionally, the following length restrictions are enforced based on the
/// guidelines from the spec:
///
/// - Minimum length: **8**-bytes
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
/// > stack allocated buffer.
///
/// Based on this guidance, this type enforces an upper bound of 48-bytes
/// as a reasonable maximum, and recommends using 16-bytes.
///
/// [1]: https://en.wikipedia.org/wiki/Rainbow_table
/// [2]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#function-duties
/// [3]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#argon2-encoding
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Salt {
    /// Length of the salt in bytes.
    pub(super) length: u8,

    /// Byte array containing an ASCII-encoded string.
    pub(super) bytes: [u8; Self::MAX_LENGTH],
}

#[allow(clippy::len_without_is_empty)]
impl Salt {
    /// Minimum length of a [`Salt`] (after "B64" decoding): 8-bytes.
    pub const MIN_LENGTH: usize = 8;

    /// Maximum length of a [`Salt`] (after "B64" decoding): 48-bytes.
    ///
    /// See type-level documentation about [`Salt`] for more information.
    pub const MAX_LENGTH: usize = 48;

    /// Recommended length of a salt: 16-bytes.
    ///
    /// This recommendation comes from the [PHC string format specification]:
    ///
    /// > The role of salts is to achieve uniqueness. A *random* salt is fine
    /// > for that as long as its length is sufficient; a 16-byte salt would
    /// > work well (by definition, UUID are very good salts, and they encode
    /// > over exactly 16 bytes). 16 bytes encode as 22 characters in B64.
    ///
    /// [PHC string format specification]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#function-duties
    pub const RECOMMENDED_LENGTH: usize = 16;

    /// Generate a random [`Salt`] with the `RECOMMENDED_LENGTH`..
    #[cfg(feature = "getrandom")]
    pub fn generate() -> Self {
        let mut bytes = [0u8; Self::RECOMMENDED_LENGTH];
        getrandom::fill(&mut bytes).expect("RNG failure");
        Self::new(&bytes).expect(INVARIANT_VIOLATED_MSG)
    }

    /// Generate a random [`Salt`] from the given [`CryptoRng`].
    #[cfg(feature = "rand_core")]
    pub fn from_rng<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let Ok(out) = Self::try_from_rng(rng);
        out
    }

    /// Generate a random [`Salt`] from the given [`TryCryptoRng`].
    #[cfg(feature = "rand_core")]
    pub fn try_from_rng<R: TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> core::result::Result<Self, R::Error> {
        let mut bytes = [0u8; Self::RECOMMENDED_LENGTH];
        rng.try_fill_bytes(&mut bytes)?;
        Ok(Self::new(&bytes).expect(INVARIANT_VIOLATED_MSG))
    }

    /// Create a new [`Salt`] from the given byte slice.
    pub fn new(slice: &[u8]) -> Result<Self> {
        if slice.len() < Self::MIN_LENGTH {
            return Err(Error::SaltInvalid(InvalidValue::TooShort));
        }

        let mut bytes = [0; Self::MAX_LENGTH];
        bytes
            .get_mut(..slice.len())
            .ok_or(Error::SaltInvalid(InvalidValue::TooLong))?
            .copy_from_slice(slice);

        debug_assert!(slice.len() >= Self::MIN_LENGTH);
        debug_assert!(slice.len() <= Self::MAX_LENGTH);

        Ok(Self {
            bytes,
            length: slice.len() as u8,
        })
    }

    /// Create a [`Salt`] from the given B64-encoded input string, validating
    /// [`Salt::MIN_LENGTH`] and [`Salt::MAX_LENGTH`] restrictions.
    pub fn from_b64(b64: &str) -> Result<Self> {
        if b64.len() < SaltString::MIN_LENGTH {
            return Err(Error::SaltInvalid(InvalidValue::TooShort));
        }

        if b64.len() > SaltString::MAX_LENGTH {
            return Err(Error::SaltInvalid(InvalidValue::TooLong));
        }

        let mut bytes = [0; Self::MAX_LENGTH];
        let length = B64::decode(b64, &mut bytes)?.len();
        debug_assert!(length <= Self::MAX_LENGTH);

        Ok(Self {
            bytes,
            length: length as u8,
        })
    }

    /// Encode this [`Salt`] as a "B64" [`SaltString`].
    pub fn to_salt_string(&self) -> SaltString {
        self.into()
    }
}

impl AsRef<[u8]> for Salt {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..(self.length as usize)]
    }
}

impl Deref for Salt {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_ref()
    }
}

impl FromStr for Salt {
    type Err = Error;

    fn from_str(b64: &str) -> Result<Self> {
        Self::from_b64(b64)
    }
}

impl TryFrom<&[u8]> for Salt {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self> {
        Self::new(slice)
    }
}

impl TryFrom<&str> for Salt {
    type Error = Error;

    fn try_from(b64: &str) -> Result<Self> {
        Self::from_b64(b64)
    }
}

impl fmt::Display for Salt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.to_salt_string().fmt(f)
    }
}

impl fmt::Debug for Salt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Salt").field(&self.as_ref()).finish()
    }
}

/// Owned stack-allocated equivalent of [`Salt`].
#[derive(Clone, Eq)]
pub struct SaltString(StringBuf<{ SaltString::MAX_LENGTH }>);

#[allow(clippy::len_without_is_empty)]
impl SaltString {
    /// Minimum length of "B64"-encoded [`SaltString`] string: 11-bytes (4-bytes encoded as "B64")
    pub const MIN_LENGTH: usize = 11;

    /// Maximum length of a "B64"-encoded [`SaltString`]: 64-bytes (48-bytes encoded as "B64")
    ///
    /// See type-level documentation about [`Salt`] for more information.
    pub const MAX_LENGTH: usize = 64;

    /// Generate a random B64-encoded [`SaltString`].
    #[cfg(feature = "getrandom")]
    pub fn generate() -> Self {
        Salt::generate().into()
    }

    /// Generate a random B64-encoded [`SaltString`] from [`CryptoRng`].
    #[cfg(feature = "rand_core")]
    pub fn from_rng<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let Ok(out) = Self::try_from_rng(rng);
        out
    }

    /// Generate a random B64-encoded [`SaltString`] from [`TryCryptoRng`].
    #[cfg(feature = "rand_core")]
    pub fn try_from_rng<R: TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> core::result::Result<Self, R::Error> {
        Ok(Salt::try_from_rng(rng)?.to_salt_string())
    }

    /// Create a new [`SaltString`] from the given B64-encoded input string,
    /// validating [`Salt::MIN_LENGTH`] and [`Salt::MAX_LENGTH`] restrictions.
    pub fn from_b64(s: &str) -> Result<Self> {
        // Assert `s` parses successfully as a `Salt`
        Salt::from_b64(s)?;
        Ok(Self(s.parse()?))
    }

    /// Decode this "B64" string, returning a [`Salt`] containing the decoded bytes.
    pub fn to_salt(&self) -> Salt {
        self.into()
    }
}

impl AsRef<str> for SaltString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for SaltString {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl From<Salt> for SaltString {
    fn from(salt: Salt) -> Self {
        SaltString::from(&salt)
    }
}

impl From<&Salt> for SaltString {
    fn from(salt: &Salt) -> Self {
        let mut buf = [0; SaltString::MAX_LENGTH];
        let b64 = B64::encode(salt, &mut buf).expect(INVARIANT_VIOLATED_MSG);
        SaltString(b64.parse().expect(INVARIANT_VIOLATED_MSG))
    }
}

impl From<SaltString> for Salt {
    fn from(salt: SaltString) -> Self {
        Salt::from(&salt)
    }
}

impl From<&SaltString> for Salt {
    fn from(salt: &SaltString) -> Self {
        Salt::from_b64(salt.as_ref()).expect(INVARIANT_VIOLATED_MSG)
    }
}

impl FromStr for SaltString {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_b64(s)
    }
}

impl PartialEq for SaltString {
    fn eq(&self, other: &Self) -> bool {
        // Ensure comparisons always honor the initialized portion of the buffer
        self.as_ref().eq(other.as_ref())
    }
}

impl fmt::Display for SaltString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl fmt::Debug for SaltString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SaltString({:?})", self.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, Salt};
    use crate::errors::InvalidValue;

    #[test]
    fn new_with_valid_min_length_input() {
        let s = "abcdabcdabc";
        let salt = Salt::from_b64(s).unwrap();
        assert_eq!(
            salt.as_ref(),
            &[0x69, 0xb7, 0x1d, 0x69, 0xb7, 0x1d, 0x69, 0xb7]
        );
    }

    #[test]
    fn new_with_valid_max_length_input() {
        let s = "012345678911234567892123456789312345678941234567";
        let salt = Salt::from_b64(s).unwrap();
        assert_eq!(
            salt.as_ref(),
            &[
                0xd3, 0x5d, 0xb7, 0xe3, 0x9e, 0xbb, 0xf3, 0xdd, 0x75, 0xdb, 0x7e, 0x39, 0xeb, 0xbf,
                0x3d, 0xdb, 0x5d, 0xb7, 0xe3, 0x9e, 0xbb, 0xf3, 0xdd, 0xf5, 0xdb, 0x7e, 0x39, 0xeb,
                0xbf, 0x3d, 0xe3, 0x5d, 0xb7, 0xe3, 0x9e, 0xbb
            ]
        );
    }

    #[test]
    fn reject_new_too_short() {
        for &too_short in &["", "a", "ab", "abc"] {
            let err = Salt::from_b64(too_short).err().unwrap();
            assert_eq!(err, Error::SaltInvalid(InvalidValue::TooShort));
        }
    }

    #[test]
    fn reject_new_too_long() {
        let s = "01234567891123456789212345678931234567894123456785234567896234567";
        let err = Salt::from_b64(s).err().unwrap();
        assert_eq!(err, Error::SaltInvalid(InvalidValue::TooLong));
    }

    #[test]
    fn reject_new_invalid_char() {
        let s = "01234_abcde";
        let err = Salt::from_b64(s).err().unwrap();
        assert_eq!(err, Error::B64Encoding(base64ct::Error::InvalidEncoding));
    }
}
