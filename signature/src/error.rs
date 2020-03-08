//! Signature error types

use core::fmt::{self, Display};

#[cfg(feature = "std")]
use std::boxed::Box;

/// Box containing a thread-safe + `'static` error suitable for use as a
/// as an `std::error::Error::source`
#[cfg(feature = "std")]
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Signature errors
#[derive(Debug, Default)]
pub struct Error {
    /// Source of the error (if applicable).
    #[cfg(feature = "std")]
    source: Option<BoxError>,
}

impl Error {
    /// Create a new error with no associated source
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new error with an associated source.
    ///
    /// **NOTE:** The "source" should NOT be used to propagate cryptographic
    /// errors e.g. signature parsing or verification errors. The intended use
    /// cases are for propagating errors related to external signers, e.g.
    /// communication/authentication errors with HSMs, KMS, etc.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn from_source(source: impl Into<BoxError>) -> Self {
        Self {
            source: Some(source.into()),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("signature error")
    }
}

#[cfg(feature = "std")]
impl From<BoxError> for Error {
    fn from(source: BoxError) -> Error {
        Self::from_source(source)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source.as_ref() as &(dyn std::error::Error + 'static))
    }
}
