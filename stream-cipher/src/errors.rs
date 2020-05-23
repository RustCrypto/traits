use core::fmt;

/// Error which notifies that stream cipher has reached the end of a keystream.
#[derive(Copy, Clone, Debug)]
pub struct LoopError;

impl fmt::Display for LoopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("Loop Error")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LoopError {}

/// Error which notifies that key or/and nonce used in stream cipher
/// initialization had an invalid length.
#[derive(Copy, Clone, Debug)]
pub struct InvalidKeyNonceLength;

impl fmt::Display for InvalidKeyNonceLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("Loop Error")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidKeyNonceLength {}
