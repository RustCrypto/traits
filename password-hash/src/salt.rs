//! Salt string support implementing the PHC string format specification's
//! RECOMMENDED best practices.

use crate::{b64, errors::SaltError};
use core::{
    convert::TryFrom,
    fmt,
    ops::Deref,
    str::{self, FromStr},
};

#[cfg(feature = "rand_core")]
use rand_core::{CryptoRng, RngCore};

/// Recommended length of a [`Salt`] according to the [PHC string format][1].
///
/// [1]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#function-duties
#[cfg(feature = "rand_core")]
const RECOMMENDED_LENGTH: usize = 16;

/// Maximum length of a [`Salt`].
const MAX_LENGTH: usize = 48;

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
/// The above guidelines are interpreted into the following constraints:
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
pub struct Salt {
    /// Byte array containing a salt value.
    bytes: [u8; MAX_LENGTH],

    /// Length of the salt in bytes.
    length: u8,
}

impl Salt {
    /// Minimum length of a [`Salt`] string: 2-bytes.
    ///
    /// NOTE: this is below the recommended
    pub const fn min_len() -> usize {
        4
    }

    /// Maximum length of a [`Salt`] string: 48-bytes.
    ///
    /// See type-level documentation about [`Salt`] for more information.
    pub const fn max_len() -> usize {
        MAX_LENGTH
    }

    /// Maximum length of a [`Salt`] when encoded as [`b64`] string: 64-bytes
    /// (i.e. 64 ASCII characters)
    pub const fn b64_max_len() -> usize {
        (MAX_LENGTH * 4) / 3
    }

    /// Generate a random [`Salt`] using the provided [`CryptoRng`].
    ///
    /// Uses the [PHC string format's recommended guidelines][1] of a 16-byte
    /// salt value:
    ///
    /// > The role of salts is to achieve uniqueness. A random salt is fine for
    /// > that as long as its length is sufficient; a 16-byte salt would work
    /// > well (by definition, UUID are very good salts, and they encode over
    /// > exactly 16 bytes).
    ///
    /// [1]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#function-duties
    #[cfg(feature = "rand_core")]
    pub fn random(mut rng: impl CryptoRng + RngCore) -> Self {
        let mut bytes = [0u8; MAX_LENGTH];
        rng.fill_bytes(&mut bytes[..RECOMMENDED_LENGTH]);

        Self {
            bytes,
            length: RECOMMENDED_LENGTH as u8,
        }
    }

    /// Create a [`Salt`] from the given byte slice, validating it according
    /// to [`Salt::min_len`] and [`Salt::max_len`] length restrictions.
    pub fn new(input: &[u8]) -> Result<Self, SaltError> {
        if input.len() < Self::min_len() {
            return Err(SaltError::TooShort);
        }

        if input.len() > Self::max_len() {
            return Err(SaltError::TooLong);
        }

        let mut bytes = [0u8; MAX_LENGTH];
        bytes[..input.len()].copy_from_slice(input);

        Ok(Self {
            bytes,
            length: input.len() as u8,
        })
    }

    /// Parse a [`b64`]-encoded salt string, i.e. using the PHC string
    /// specification's restricted interpretation of Base64.
    pub fn b64_decode(input: &str) -> Result<Self, SaltError> {
        if b64::decoded_len(input) > MAX_LENGTH {
            return Err(SaltError::TooLong);
        }

        let mut bytes = [0u8; MAX_LENGTH];
        b64::decode(input, &mut bytes)
            .map_err(Into::into)
            .and_then(Self::new)
    }

    /// Write [`b64`]-encoded salt string to the provided buffer, returning
    /// a sub-slice containing the encoded data.
    ///
    /// Returns an error if the buffer is too short to contain the output.
    pub fn b64_encode<'a>(&self, out: &'a mut [u8]) -> Result<&'a str, SaltError> {
        Ok(b64::encode(self.as_ref(), out)?)
    }

    /// Get the length of this salt string when encoded as [`b64`].
    pub fn b64_len(&self) -> usize {
        b64::encoded_len(self.as_ref())
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
    type Err = SaltError;

    fn from_str(s: &str) -> Result<Self, SaltError> {
        Self::b64_decode(s)
    }
}

impl TryFrom<&[u8]> for Salt {
    type Error = SaltError;

    fn try_from(input: &[u8]) -> Result<Salt, SaltError> {
        Self::new(input)
    }
}

impl fmt::Display for Salt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buffer = [0u8; Self::b64_max_len()];
        f.write_str(self.b64_encode(&mut buffer).map_err(|_| fmt::Error)?)
    }
}

impl fmt::Debug for Salt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Salt(\"{}\")", self)
    }
}

#[cfg(test)]
mod tests {
    use super::{Salt, SaltError};

    #[test]
    fn new_with_valid_min_length_input() {
        let bytes = [4u8; 4];
        let salt = Salt::new(&bytes).unwrap();
        assert_eq!(salt.as_ref(), &bytes);
    }

    #[test]
    fn new_with_valid_max_length_input() {
        let bytes = [48u8; 48];
        let salt = Salt::new(&bytes).unwrap();
        assert_eq!(salt.as_ref(), &bytes);
    }

    #[test]
    fn reject_new_too_short() {
        for &too_short in &[&b""[..], &b"\x01"[..], &b"\x02\x02"[..], &b"\x03\x03"[..]] {
            let err = Salt::new(too_short).err().unwrap();
            assert_eq!(err, SaltError::TooShort);
        }
    }

    #[test]
    fn reject_new_too_long() {
        let bytes = [49u8; 49];
        let err = Salt::new(&bytes).err().unwrap();
        assert_eq!(err, SaltError::TooLong);
    }
}
