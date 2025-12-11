//! Error types.

use core::fmt;

/// Result type.
pub type Result<T> = core::result::Result<T, Error>;

/// Password hashing errors.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Unsupported algorithm.
    Algorithm,

    /// Cryptographic error.
    Crypto,

    /// Encoding errors (e.g. Base64).
    EncodingInvalid,

    /// Internal error within a password hashing library.
    Internal,

    /// Out of memory (heap allocation failure).
    OutOfMemory,

    /// Output size invalid.
    OutputSize,

    /// Invalid named parameter.
    ParamInvalid {
        /// Parameter name.
        name: &'static str,
    },

    /// Invalid parameters.
    ParamsInvalid,

    /// Invalid password.
    PasswordInvalid,

    /// Invalid salt.
    SaltInvalid,

    /// Invalid algorithm version.
    Version,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> core::result::Result<(), fmt::Error> {
        match self {
            Self::Algorithm => write!(f, "unsupported algorithm"),
            Self::Crypto => write!(f, "cryptographic error"),
            Self::EncodingInvalid => write!(f, "invalid encoding"),
            Self::Internal => write!(f, "internal password hashing algorithm error"),
            Self::OutOfMemory => write!(f, "out of memory"),
            Self::OutputSize => write!(f, "password hash output size invalid"),
            Self::ParamInvalid { name } => write!(f, "invalid parameter: {name:?}"),
            Self::ParamsInvalid => write!(f, "invalid parameters"),
            Self::PasswordInvalid => write!(f, "invalid password"),
            Self::SaltInvalid => write!(f, "invalid salt"),
            Self::Version => write!(f, "invalid algorithm version"),
        }
    }
}

impl core::error::Error for Error {}

#[cfg(feature = "phc")]
impl From<phc::Error> for Error {
    fn from(err: phc::Error) -> Self {
        match err {
            phc::Error::B64Encoding(_) | phc::Error::MissingField | phc::Error::TrailingData => {
                Self::EncodingInvalid
            }
            phc::Error::OutputSize { .. } => Self::OutputSize,
            phc::Error::ParamNameDuplicated
            | phc::Error::ParamNameInvalid
            | phc::Error::ParamValueTooLong
            | phc::Error::ParamsMaxExceeded
            | phc::Error::ValueTooLong => Self::ParamsInvalid,
            phc::Error::SaltTooShort | phc::Error::SaltTooLong => Self::SaltInvalid,
            _ => Self::Internal, // Branch since `phc::Error` is `non_exhaustive`
        }
    }
}
