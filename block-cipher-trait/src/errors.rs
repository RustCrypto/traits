use core::fmt;
#[cfg(feature = "std")]
use std::error;

/// Error struct which used with `NewVarKey`
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct InvalidKeyLength;

impl fmt::Display for InvalidKeyLength {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid key length")
    }
}

#[cfg(feature = "std")]
impl error::Error for InvalidKeyLength {
    fn description(&self) -> &str {
        "invalid key length"
    }
}
