//! SHA-crypt variants.
//!
//! <https://www.akkadia.org/drepper/SHA-crypt.txt>

use crate::Ident;
use core::fmt;

/// SHA-crypt (SHA-256)
///
/// See [`Variant::Sha256`] for more information.
pub const SHACRYPT_SHA256: Ident = Ident::new("5");

/// SHA-crypt (SHA-512)
///
/// See [`Variant::Sha512`] for more information.
pub const SHACRYPT_SHA512: Ident = Ident::new("6");

/// SHA-crypt variants.
///
/// <https://www.akkadia.org/drepper/SHA-crypt.txt>
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Variant {
    /// SHA-crypt with SHA-256 (`$5$`)
    Sha256,

    /// SHA-crypt with SHA-512 (`$6$`)
    Sha512,
}

impl Variant {
    /// Get the [`Ident`] that corresponds to this SHA-crypt [`Variant`].
    pub fn ident(&self) -> &Ident {
        match self {
            Variant::Sha256 => &SHACRYPT_SHA256,
            Variant::Sha512 => &SHACRYPT_SHA512,
        }
    }

    /// Get the identifier string for this SHA-crypt [`Variant`].
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
