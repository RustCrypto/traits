//! Outputs from password hashing functions.

use crate::{b64, errors::OutputError};
use core::{cmp::PartialEq, convert::TryFrom, fmt, str::FromStr};

/// Maximum length of password hash function outputs.
const MAX_LENGTH: usize = 64;

/// Output from password hashing functions, i.e. the "hash" or "digest"
/// as raw bytes.
///
/// The [`Output`] type implements the RECOMMENDED best practices described in
/// the [PHC string format specification][1], namely:
///
/// > The hash output, for a verification, must be long enough to make preimage
/// > attacks at least as hard as password guessing. To promote wide acceptance,
/// > a default output size of 256 bits (32 bytes, encoded as 43 characters) is
/// > recommended. Function implementations SHOULD NOT allow outputs of less
/// > than 80 bits to be used for password verification.
///
/// # Recommended length
/// Per the description above, the recommended default length for an [`Output`]
/// of a password hashing function is **32-bytes** (256-bits).
///
/// # Constraints
/// The above guidelines are interpreted into the following constraints:
///
/// - Minimum length: **10**-bytes (80-bits)
/// - Maximum length: **64**-bytes (512-bits)
///
/// The specific recommendation of a 64-byte maximum length is taken as a best
/// practice from the hash output guidelines for [Argon2 Encoding][2] given in
/// the same document:
///
/// > The hash output...length shall be between 12 and 64 bytes (16 and 86
/// > characters, respectively). The default output length is 32 bytes
/// > (43 characters).
///
/// Based on this guidance, this type enforces an upper bound of 64-bytes
/// as a reasonable maximum, and recommends using 32-bytes.
///
/// # Constant-time comparisons
/// The [`PartialEq`] and [`Eq`] trait impls for [`Output`] provide a
/// non-short-circuiting equality comparison.
///
/// There are few cases where this may actually helpful from a practical
/// perspective, namely cases where salts are predictable by an attacker.
/// Due to the limited degree in which such comparisons may be helpful,
/// this crate does not loop in additional dependencies for
/// constant-time comparisons (e.g. `subtle`).
///
/// The extent to which constant-time comparisons of password hashes is
/// actually helpful in practical contexts [topic of considerable debate][3].
/// This library has elected to use a non-short-circuiting comparison as a
/// safer ("belt-and-suspenders") default, and also to
/// [head off any potential debates around the issue][4].
///
/// [1]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#function-duties
/// [2]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#argon2-encoding
/// [3]: https://github.com/codahale/bcrypt-ruby/issues/42
/// [4]: https://twitter.com/coda/status/866310352606068736
#[derive(Copy, Clone, Eq)]
pub struct Output {
    /// Byte array containing a password hashing function output.
    bytes: [u8; MAX_LENGTH],

    /// Length of the password hashing function output in bytes.
    length: u8,
}

#[allow(clippy::len_without_is_empty)]
impl Output {
    /// Minimum length of [`Output`] string: 10-bytes.
    ///
    /// See type-level documentation about [`Output`] for more information.
    pub const fn min_len() -> usize {
        10
    }

    /// Maximum length of [`Output`] string: 64-bytes.
    ///
    /// See type-level documentation about [`Output`] for more information.
    pub const fn max_len() -> usize {
        MAX_LENGTH
    }

    /// Maximum length of [`Output`] when encoded as [`b64`] string: 86-bytes
    /// (i.e. 86 ASCII characters)
    pub const fn b64_max_len() -> usize {
        ((MAX_LENGTH * 4) / 3) + 1
    }

    /// Create a [`Output`] from the given byte slice, validating it according
    /// to [`Output::min_len`] and [`Output::max_len`] length restrictions.
    pub fn new(input: &[u8]) -> Result<Self, OutputError> {
        Self::init_with(input.len(), |bytes| {
            bytes.copy_from_slice(input);
            Ok(())
        })
    }

    /// Initialize an [`Output`] using the provided method, which is given
    /// a mutable byte slice into which it should write the output.
    ///
    /// The `output_size` (in bytes) must be known in advance, as well as at
    /// least [`Output::min_len`] bytes and at most [`Output::max_len`] bytes.
    pub fn init_with<F>(output_size: usize, f: F) -> Result<Self, OutputError>
    where
        F: FnOnce(&mut [u8]) -> Result<(), OutputError>,
    {
        if output_size < Self::min_len() {
            return Err(OutputError::TooShort);
        }

        if output_size > Self::max_len() {
            return Err(OutputError::TooLong);
        }

        let mut bytes = [0u8; MAX_LENGTH];
        f(&mut bytes[..output_size])?;

        Ok(Self {
            bytes,
            length: output_size as u8,
        })
    }

    /// Borrow the output value as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len()]
    }

    /// Get the length of the output value as a byte slice.
    pub fn len(&self) -> usize {
        usize::from(self.length)
    }

    /// Parse [`b64`]-encoded [`Output`], i.e. using the PHC string
    /// specification's restricted interpretation of Base64.
    pub fn b64_decode(input: &str) -> Result<Self, OutputError> {
        let mut bytes = [0u8; MAX_LENGTH];
        b64::decode(input, &mut bytes)
            .map_err(Into::into)
            .and_then(Self::new)
    }

    /// Write [`b64`]-encoded [`Output`] to the provided buffer, returning
    /// a sub-slice containing the encoded data.
    ///
    /// Returns an error if the buffer is too short to contain the output.
    pub fn b64_encode<'a>(&self, out: &'a mut [u8]) -> Result<&'a str, OutputError> {
        Ok(b64::encode(self.as_ref(), out)?)
    }

    /// Get the length of this [`Output`] when encoded as [`b64`].
    pub fn b64_len(&self) -> usize {
        b64::encoded_len(self.as_ref())
    }
}

impl AsRef<[u8]> for Output {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl FromStr for Output {
    type Err = OutputError;

    fn from_str(s: &str) -> Result<Self, OutputError> {
        Self::b64_decode(s)
    }
}

impl PartialEq for Output {
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }

        // Non-short-circuiting comparison.
        // See "Constant-time comparisons" documentation above.
        self.as_ref()
            .iter()
            .zip(other.as_ref().iter())
            .fold(0, |acc, (a, b)| acc | (a ^ b))
            == 0
    }
}

impl TryFrom<&[u8]> for Output {
    type Error = OutputError;

    fn try_from(input: &[u8]) -> Result<Output, OutputError> {
        Self::new(input)
    }
}

impl fmt::Display for Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buffer = [0u8; Self::b64_max_len()];
        f.write_str(self.b64_encode(&mut buffer).map_err(|_| fmt::Error)?)
    }
}

impl fmt::Debug for Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Output(\"{}\")", self)
    }
}

#[cfg(test)]
mod tests {
    use super::{Output, OutputError};

    #[test]
    fn new_with_valid_min_length_input() {
        let bytes = [10u8; 10];
        let output = Output::new(&bytes).unwrap();
        assert_eq!(output.as_ref(), &bytes);
    }

    #[test]
    fn new_with_valid_max_length_input() {
        let bytes = [64u8; 64];
        let output = Output::new(&bytes).unwrap();
        assert_eq!(output.as_ref(), &bytes);
    }

    #[test]
    fn reject_new_too_short() {
        let bytes = [9u8; 9];
        let err = Output::new(&bytes).err().unwrap();
        assert_eq!(err, OutputError::TooShort);
    }

    #[test]
    fn reject_new_too_long() {
        let bytes = [65u8; 65];
        let err = Output::new(&bytes).err().unwrap();
        assert_eq!(err, OutputError::TooLong);
    }

    #[test]
    fn partialeq_true() {
        let a = Output::new(&[1u8; 32]).unwrap();
        let b = Output::new(&[1u8; 32]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn partialeq_false() {
        let a = Output::new(&[1u8; 32]).unwrap();
        let b = Output::new(&[2u8; 32]).unwrap();
        assert_ne!(a, b);
    }
}
