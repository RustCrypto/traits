//! Signature error types

use core::fmt::{self, Debug, Display};

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

/// Result type.
///
/// A result with the `signature` crate's [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;

/// Signature errors.
///
/// This type is deliberately opaque as to avoid sidechannel leakage which
/// could potentially be used recover signing private keys or forge signatures
/// (e.g. [BB'06]).
///
/// When the `alloc` feature is enabled, it supports an optional [`core::error::Error::source`],
/// which can be used by things like remote signers (e.g. HSM, KMS) to report I/O or auth errors.
///
/// [BB'06]: https://en.wikipedia.org/wiki/Daniel_Bleichenbacher
#[derive(Clone, Copy)]
pub struct Error;

impl Error {
    /// DEPRECATED: create a new error.
    #[deprecated(since = "3.0.0", note = "use `Error` instead (no constructor needed)")]
    pub fn new() -> Self {
        Error
    }
}

impl Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("signature::Error").finish()
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("signature error")
    }
}

impl core::error::Error for Error {}
