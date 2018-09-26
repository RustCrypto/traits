use core::fmt;
#[cfg(feature = "std")]
use std::error;

/// Error type for signaling failed MAC verification
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub struct MacError;

/// Error type for signaling invalid key length for MAC initialization
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub struct InvalidKeyLength;


impl fmt::Display for MacError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("failed MAC verification")
    }
}

impl fmt::Display for InvalidKeyLength {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid key length")
    }
}

#[cfg(feature = "std")]
impl error::Error for MacError {
    fn description(&self) -> &str {
        "failed MAC verification"
    }
}

#[cfg(feature = "std")]
impl error::Error for InvalidKeyLength {
    fn description(&self) -> &str {
        "invalid key length"
    }
}