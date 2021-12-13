//! KEM error types

use core::fmt::{Debug, Display};

/// Represents KEM errors. This is intentionally opaque to avoid leaking information about private
/// keys through side channels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error;

impl Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "error encapsulating or eecapsulating")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
