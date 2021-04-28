//! Error types.

pub use base64ct::Error as B64Error;

use core::fmt;

/// Result type.
pub type Result<T> = core::result::Result<T, Error>;

/// Password hashing errors.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Unsupported algorithm.
    Algorithm,

    /// "B64" encoding error.
    B64(B64Error),

    /// Cryptographic error.
    Crypto,

    /// Output too short (min 10-bytes).
    OutputTooShort,

    /// Output too long (max 64-bytes).
    OutputTooLong,

    /// Duplicate parameter name encountered.
    ParamNameDuplicated,

    /// Invalid parameter name.
    ParamNameInvalid,

    /// Invalid parameter value.
    ParamValueInvalid,

    /// Maximum number of parameters exceeded.
    ParamsMaxExceeded,

    /// Invalid password.
    Password,

    /// Password hash string contains invalid characters.
    PhcStringInvalid,

    /// Password hash string too short.
    PhcStringTooShort,

    /// Password hash string too long.
    PhcStringTooLong,

    /// Salt too short.
    SaltTooShort,

    /// Salt too long.
    SaltTooLong,

    /// Invalid algorithm version.
    Version,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> core::result::Result<(), fmt::Error> {
        match self {
            Self::Algorithm => write!(f, "unsupported algorithm"),
            Self::B64(err) => write!(f, "{}", err),
            Self::Crypto => write!(f, "cryptographic error"),
            Self::OutputTooShort => f.write_str("PHF output too short (min 10-bytes)"),
            Self::OutputTooLong => f.write_str("PHF output too long (max 64-bytes)"),
            Self::ParamNameDuplicated => f.write_str("duplicate parameter"),
            Self::ParamNameInvalid => f.write_str("invalid parameter name"),
            Self::ParamValueInvalid => f.write_str("invalid parameter value"),
            Self::ParamsMaxExceeded => f.write_str("maximum number of parameters reached"),
            Self::Password => write!(f, "invalid password"),
            Self::PhcStringInvalid => write!(f, "password hash string invalid"),
            Self::PhcStringTooShort => write!(f, "password hash string too short"),
            Self::PhcStringTooLong => write!(f, "password hash string too long"),
            Self::SaltTooShort => write!(f, "salt too short"),
            Self::SaltTooLong => write!(f, "salt too long"),
            Self::Version => write!(f, "invalid algorithm version"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl From<B64Error> for Error {
    fn from(err: B64Error) -> Error {
        Error::B64(err)
    }
}

impl From<base64ct::InvalidLengthError> for Error {
    fn from(_: base64ct::InvalidLengthError) -> Error {
        Error::B64(B64Error::InvalidLength)
    }
}
