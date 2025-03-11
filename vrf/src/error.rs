//! VRF error types
//!
//! This module defines error handling types for Verifiable Random Function (VRF)
//! operations. The error type is intentionally minimal to prevent potential
//! side-channel leaks that could compromise the security of VRF-related
//! cryptographic operations.

use core::{error, fmt};

/// Result type.
///
/// A specialized result type alias for VRF operations, using the [`Error`] type
/// defined in this module.
pub type Result<T> = core::result::Result<T, Error>;

/// VRF errors.
///
/// This type represents errors that may occur during VRF operations. It is
/// designed to be opaque to avoid exposing internal details that could be
/// exploited in cryptographic attacks. Currently, it does not include a source
/// field, but it is marked as `non_exhaustive` to allow for future extensions.
#[derive(Default)]
#[non_exhaustive]
pub struct Error {}

impl Error {
    /// Creates a new VRF error.
    fn new() -> Self {
        Self::default()
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("vrf::Error {}")
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("vrf::Error {}")
    }
}

impl error::Error for Error {
    /// Returns the source of the error, if any.
    ///
    /// Since this implementation does not currently support a source, this
    /// method always returns `None`. This behavior may change in future
    /// iterations if the error type is extended.
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        None
    }
}
