//! Error types.

use core::fmt;

#[cfg(docsrs)]
use crate::PasswordHasher;

/// "B64" encoding errors.
///
///<https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#b64>
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum B64Error {
    /// Encoding error.
    EncodingInvalid,

    /// Invalid length.
    LengthInvalid,

    /// Trailing whitespace characters.
    TrailingWhitespace,
}

impl fmt::Display for B64Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::EncodingInvalid => f.write_str("invalid B64 encoding"),
            Self::LengthInvalid => f.write_str("B64 encoded data has invalid length"),
            Self::TrailingWhitespace => f.write_str("B64 encoded data has trailing whitespace"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for B64Error {}

/// Password hash errors.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HashError {
    /// Hash output error.
    Hash(OutputError),

    /// Params error.
    Params(ParamsError),

    /// Parse error.
    Parse(ParseError),
}

impl fmt::Display for HashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Hash(err) => write!(f, "invalid password hash: {}", err),
            Self::Params(err) => write!(f, "invalid params: {}", err),
            Self::Parse(err) => write!(f, "parse error: {}", err),
        }
    }
}

impl From<OutputError> for HashError {
    fn from(err: OutputError) -> HashError {
        HashError::Hash(err)
    }
}

impl From<ParamsError> for HashError {
    fn from(err: ParamsError) -> HashError {
        match err {
            ParamsError::Parse(e) => e.into(),
            _ => HashError::Params(err),
        }
    }
}

impl From<ParseError> for HashError {
    fn from(err: ParseError) -> HashError {
        HashError::Parse(err)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HashError {}

/// Errors generating password hashes using a [`PasswordHasher`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HasherError {
    /// Unsupported algorithm.
    Algorithm,

    /// Cryptographic error.
    Crypto,

    /// Error generating output.
    Output(OutputError),

    /// Invalid parameter.
    Param,

    /// Parse error.
    Parse(ParseError),

    /// Invalid password.
    Password,
}

impl fmt::Display for HasherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Algorithm => write!(f, "unsupported algorithm"),
            Self::Crypto => write!(f, "cryptographic error"),
            Self::Output(err) => write!(f, "PHF output error: {}", err),
            Self::Param => write!(f, "invalid algorithm parameter"),
            Self::Parse(err) => write!(f, "{}", err),
            Self::Password => write!(f, "invalid password"),
        }
    }
}

impl From<OutputError> for HasherError {
    fn from(err: OutputError) -> HasherError {
        HasherError::Output(err)
    }
}

impl From<ParseError> for HasherError {
    fn from(err: ParseError) -> HasherError {
        HasherError::Parse(err)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HasherError {}

/// Parameter-related errors.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ParamsError {
    /// Duplicate parameter name encountered.
    DuplicateName,

    /// Maximum number of parameters exceeded.
    MaxExceeded,

    /// Parse errors.
    Parse(ParseError),
}

impl fmt::Display for ParamsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::DuplicateName => f.write_str("duplicate parameter"),
            Self::MaxExceeded => f.write_str("maximum number of parameters reached"),
            Self::Parse(err) => write!(f, "{}", err),
        }
    }
}

impl From<ParseError> for ParamsError {
    fn from(err: ParseError) -> ParamsError {
        Self::Parse(err)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParamsError {}

/// Parse errors.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// Invalid empty input.
    Empty,

    /// Input contains invalid character.
    InvalidChar(char),

    /// Input too short.
    TooShort,

    /// Input too long.
    TooLong,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Empty => f.write_str("invalid empty input"),
            Self::InvalidChar(char) => write!(f, "invalid character '{}'", char),
            Self::TooShort => f.write_str("too short"),
            Self::TooLong => f.write_str("too long"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

/// Password hash function output (i.e. hash/digest) errors.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum OutputError {
    /// "B64" encoding error.
    B64(B64Error),

    /// Output too short (min 10-bytes).
    TooShort,

    /// Output too long (max 64-bytes).
    TooLong,
}

impl fmt::Display for OutputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::B64(err) => write!(f, "{}", err),
            Self::TooShort => f.write_str("PHF output too short (min 10-bytes)"),
            Self::TooLong => f.write_str("PHF output too long (max 64-bytes)"),
        }
    }
}

impl From<B64Error> for OutputError {
    fn from(err: B64Error) -> OutputError {
        OutputError::B64(err)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OutputError {}

/// Password verification errors.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VerifyError;

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("password verification error")
    }
}

impl From<HasherError> for VerifyError {
    fn from(_: HasherError) -> VerifyError {
        VerifyError
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VerifyError {}
