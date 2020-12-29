//! PBKDF2 variants.
//!
//! <https://en.wikipedia.org/wiki/PBKDF2>

use crate::Ident;
use core::fmt;

/// PBKDF2 (SHA-1)
pub const PBKDF2_SHA1: Ident = Ident::new("pbkdf2");

/// PBKDF2 (SHA-256)
pub const PBKDF2_SHA256: Ident = Ident::new("pbkdf2-sha256");

/// PBKDF2 (SHA-512)
pub const PBKDF2_SHA512: Ident = Ident::new("pbkdf2-sha512");

/// PBKDF2 variants.
///
/// <https://en.wikipedia.org/wiki/PBKDF2>
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Variant {
    /// PBKDF2 SHA1
    Sha1,

    /// PBKDF2 SHA-256
    Sha256,

    /// PBKDF2 SHA-512
    Sha512,
}

impl Variant {
    /// Get the [`Ident`] that corresponds to this PBKDF2 [`Variant`].
    pub fn ident(&self) -> &Ident {
        match self {
            Variant::Sha1 => &PBKDF2_SHA1,
            Variant::Sha256 => &PBKDF2_SHA256,
            Variant::Sha512 => &PBKDF2_SHA512,
        }
    }

    /// Get the identifier string for this PBKDF2 [`Variant`].
    pub fn as_str(&self) -> &str {
        self.ident().as_ref()
    }
}

impl AsRef<str> for Variant {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<Variant> for Ident {
    fn from(alg: Variant) -> Ident {
        *alg.ident()
    }
}

impl fmt::Display for Variant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
