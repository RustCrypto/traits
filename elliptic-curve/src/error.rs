//! Error type.

use core::fmt::{self, Display};

/// Result type with the `elliptic-curve` crate's [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;

/// Result type for [`DecodeError`].
#[cfg(any(feature = "pkcs8", feature = "sec1"))]
pub type DecodeResult<T> = core::result::Result<T, DecodeError>;

/// Elliptic curve errors.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Error;

impl core::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("crypto error")
    }
}

impl From<base16ct::Error> for Error {
    fn from(_: base16ct::Error) -> Error {
        Error
    }
}

impl From<core::array::TryFromSliceError> for Error {
    fn from(_: core::array::TryFromSliceError) -> Error {
        Error
    }
}

#[cfg(feature = "pkcs8")]
impl From<pkcs8::Error> for Error {
    fn from(_: pkcs8::Error) -> Error {
        Error
    }
}

#[cfg(feature = "sec1")]
impl From<sec1::Error> for Error {
    fn from(_: sec1::Error) -> Error {
        Error
    }
}

/// Decoding errors for elliptic curve keys.
#[cfg(feature = "sec1")]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// Invalid PEM.
    #[cfg(feature = "pem")]
    Pem(pem_rfc7468::Error),

    /// Indicates invalid PKCS#8 EC key
    #[cfg(feature = "pkcs8")]
    Pkcs8(::pkcs8::Error),

    /// Indicates invalid SEC1 EC key
    Sec1(::sec1::Error),
}

#[cfg(feature = "pem")]
impl From<pem_rfc7468::Error> for DecodeError {
    #[inline(always)]
    fn from(error: pem_rfc7468::Error) -> Self {
        Self::Pem(error)
    }
}

#[cfg(feature = "pkcs8")]
impl From<::pkcs8::Error> for DecodeError {
    #[inline(always)]
    fn from(error: ::pkcs8::Error) -> Self {
        Self::Pkcs8(error)
    }
}

#[cfg(feature = "sec1")]
impl From<::sec1::Error> for DecodeError {
    #[inline(always)]
    fn from(error: ::sec1::Error) -> Self {
        Self::Sec1(error)
    }
}

#[cfg(feature = "sec1")]
impl Display for DecodeError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "pem")]
            Self::Pem(error) => write!(fmt, "couldn't parse PEM: {error}"),
            #[cfg(feature = "pkcs8")]
            Self::Pkcs8(error) => write!(fmt, "couldn't parse PKCS#8 key: {error}"),
            Self::Sec1(error) => write!(fmt, "couldn't parse SEC1 key: {error}"),
        }
    }
}

#[cfg(feature = "sec1")]
impl core::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            #[cfg(feature = "pem")]
            Self::Pem(error) => Some(error),
            #[cfg(feature = "pkcs8")]
            Self::Pkcs8(error) => Some(error),
            Self::Sec1(error) => Some(error),
        }
    }
}
