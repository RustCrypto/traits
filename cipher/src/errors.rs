//! Error types.

use core::fmt;

/// The error type returned when stream cipher has reached the end of a keystream.
#[derive(Copy, Clone, Debug)]
pub struct LoopError;

impl fmt::Display for LoopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("Loop Error")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LoopError {}

/// The error type returned when a cipher position can not be represented
/// by the requested type.
#[derive(Copy, Clone, Debug)]
pub struct OverflowError;

impl fmt::Display for OverflowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("Overflow Error")
    }
}

impl From<OverflowError> for LoopError {
    fn from(_: OverflowError) -> LoopError {
        LoopError
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OverflowError {}

/// The error type returned when key and/or nonce used in the [`FromKey`]
/// and [`FromKeyNonce`] slice-based methods had an invalid length.
///
/// [`FromKey`]: crate::FromKey
/// [`FromKeyNonce`]: crate::FromKeyNonce
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct InvalidLength;

impl fmt::Display for InvalidLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("Invalid Length")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidLength {}

/// The error type returned by the [`BlockModeEncryptWrapper`] and
/// [`BlockModeDecryptWrapper`] types.
///
/// [`BlockModeEncryptWrapper`]: crate::BlockModeEncryptWrapper
/// [`BlockModeDecryptWrapper`]: crate::BlockModeDecryptWrapper
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct BlockModeError;

impl fmt::Display for BlockModeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("Invalid Length")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BlockModeError {}
