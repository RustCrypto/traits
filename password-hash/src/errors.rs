//! Error types.

use crate::{Algorithm, Ident};
use core::fmt;

#[cfg(docsrs)]
use crate::PasswordHashingFunction;

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

    /// Salt error.
    Salt(SaltError),
}

impl fmt::Display for HashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Hash(err) => write!(f, "invalid password hash: {}", err),
            Self::Params(err) => write!(f, "invalid params: {}", err),
            Self::Parse(err) => write!(f, "parse error: {}", err),
            Self::Salt(err) => write!(f, "invalid salt: {}", err),
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

impl From<SaltError> for HashError {
    fn from(err: SaltError) -> HashError {
        HashError::Salt(err)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HashError {}

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

/// Parsing errors.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct ParseError {
    /// Ident contains an invalid character.
    pub invalid_char: Option<char>,

    /// Ident is too long.
    pub too_long: bool,
}

impl ParseError {
    /// Create a parse error for the case where something is too long.
    pub(crate) fn too_long() -> Self {
        Self {
            invalid_char: None,
            too_long: true,
        }
    }

    /// Did the error occur because the input string was empty?
    pub fn is_empty(self) -> bool {
        self.invalid_char.is_none() && !self.too_long
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("PHC string parse error: ")?;

        if self.is_empty() {
            return f.write_str("empty strings not permitted");
        }

        if let Some(invalid_char) = self.invalid_char {
            write!(f, "invalid character '{}'", invalid_char)?;

            if self.too_long {
                f.write_str(", ")?;
            }
        }

        if self.too_long {
            // TODO(tarcieri): include const generic maximum length
            f.write_str("too long")?;
        }

        Ok(())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

/// Errors generating password hashes using a [`PasswordHashingFunction`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PhfError {
    /// Unsupported algorithm.
    Algorithm(Algorithm),

    /// Cryptographic error.
    Crypto,

    /// Error generating output.
    Output(OutputError),

    /// Invalid parameter.
    Param(Ident),

    /// Invalid password.
    Password,
}

impl fmt::Display for PhfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Algorithm(alg) => write!(f, "unsupported algorithm: {}", alg),
            Self::Crypto => write!(f, "cryptographic error"),
            Self::Output(err) => write!(f, "PHF output error: {}", err),
            Self::Param(name) => write!(f, "invalid algorithm parameter: {}", name),
            Self::Password => write!(f, "invalid password"),
        }
    }
}

impl From<OutputError> for PhfError {
    fn from(err: OutputError) -> PhfError {
        PhfError::Output(err)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PhfError {}

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

/// Salt-related errors.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SaltError {
    /// "B64" encoding error.
    B64(B64Error),

    /// Salt too short (min 4-bytes).
    TooShort,

    /// Salt too long (max 48-bytes).
    TooLong,
}

impl fmt::Display for SaltError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::B64(err) => write!(f, "{}", err),
            Self::TooShort => f.write_str("salt too short (min 4-bytes)"),
            Self::TooLong => f.write_str("salt too long (max 48-bytes)"),
        }
    }
}

impl From<B64Error> for SaltError {
    fn from(err: B64Error) -> SaltError {
        SaltError::B64(err)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SaltError {}

/// Password verification errors.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VerifyError;

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("password verification error")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VerifyError {}
