//! Argon2 variants.
//!
//! <https://en.wikipedia.org/wiki/Argon2>

use crate::Ident;
use core::fmt;

/// Argon2d
///
/// See [`Variant::D`] for more information.
pub const ARGON2D: Ident = Ident::new("argon2d");

/// Argon2i
///
/// See [`Variant::I`] for more information.
pub const ARGON2I: Ident = Ident::new("argon2i");

/// Argon2id
///
/// See [`Variant::ID`] for more information.
pub const ARGON2ID: Ident = Ident::new("argon2id");

/// Argon2 variants.
///
/// <https://en.wikipedia.org/wiki/Argon2>
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Variant {
    /// Argon2d
    ///
    /// Maximizes time-memory tradeoff (TMTO) by accessing the memory array in
    /// a password dependent order.
    ///
    /// However, this introduces potential side-channel attacks.
    D,

    /// Argon2i
    ///
    /// Optimized to resist side-channel attacks by accessing the memory array
    /// in a password-independent order.
    ///
    /// However, this reduces the time-memory tradeoff (TMTO).
    I,

    /// Argon2id
    ///
    /// Hybrid scheme combining Argon2d and Argon2i, using the latter for a
    /// first pass over memory, and Argon2d for subsequent passes.
    ID,
}

impl Variant {
    /// Get the [`Ident`] that corresponds to this Argon2 [`Variant`].
    pub fn ident(&self) -> &Ident {
        match self {
            Variant::D => &ARGON2D,
            Variant::I => &ARGON2I,
            Variant::ID => &ARGON2ID,
        }
    }

    /// Get the identifier string for this Argon2 [`Variant`].
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
