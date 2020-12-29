//! bcrypt variants.
//!
//! - Wikipedia: <https://en.wikipedia.org/wiki/Bcrypt>
//! - Original paper: <https://www.openbsd.org/papers/bcrypt-paper.pdf>

use crate::Ident;
use core::fmt;

/// bcrypt (`$2$`).
///
/// See [`Variant::Legacy`] for more information.
pub const BCRYPT_LEGACY: Ident = Ident::new("2");

/// bcrypt (`$2a$`)
///
/// See [`Variant::A`] for more information.
pub const BCRYPT_A: Ident = Ident::new("2a");

/// bcrypt (`$2b$`)
///
/// See [`Variant::B`] for more information.
pub const BCRYPT_B: Ident = Ident::new("2b");

/// bcrypt (`$2x$`)
///
/// See [`Variant::X`] for more information.
pub const BCRYPT_X: Ident = Ident::new("2x");

/// bcrypt (`$2y$`)
///
/// See [`Variant::Y`] for more information.
pub const BCRYPT_Y: Ident = Ident::new("2y");

/// bcrypt variants.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Variant {
    /// bcrypt (`$2$`)
    ///
    /// Original OpenBSD bcrypt implementation.
    Legacy,

    /// bcrypt (`$2a$`)
    ///
    /// The original bcrypt specification did not define how to handle
    /// non-ASCII characters, or how to handle a null terminator.
    /// The specification was revised to specify that when hashing strings:
    ///
    /// - the string MUST be UTF-8 encoded
    /// - the null terminator MUST be included
    A,

    /// bcrypt (`$2b`)
    ///
    /// Introduced: February 2014
    ///
    /// A bug was discovered in the OpenBSD implementation of bcrypt which previously stored the
    /// length of a string as an unsigned char. Therefore if a password was longer than 255
    /// characters, it would overflow and wrap at 255.
    ///
    /// Hashes with this prefix were generated after the bugfix.
    ///
    /// `$2b$` is not "better" or "stronger" than `$2a$` ([`Variant::A`]), but rather a remnant of
    /// one particular buggy implementation of bcrypt (i.e. OpenBSD).
    B,

    /// bcrypt (`$2x$`)
    ///
    /// Introduced: June 2011
    ///
    /// A bug was discovered in `crypt_blowfish`, a PHP implementation of bcrypt. It was
    /// mishandling characters with the 8th bit set.
    ///
    /// The authors suggested that system administrators update their existing password database,
    /// replacing `$2a$` with `$2x$`, to indicate that those hashes are bad (and need to use the old
    /// broken algorithm). They also  Nobody else, including canonical OpenBSD, adopted
    /// the idea of 2x/2y. This version marker was was limited to crypt_blowfish.
    ///
    /// `$2x$` is not "better" or "stronger" than `$2a$` ([`Variant::A`]), but rather a remnant of
    /// one particular buggy implementation of bcrypt (i.e. `crypt_blowfish`).
    X,

    /// bcrypt (`$2y$`)
    ///
    /// Introduced: June 2011
    ///
    /// Alongside `$2x$` ([`Variant::X`]), the authors of `crypt_blowfish` suggested the idea of
    /// emitting `$2y$` for hashes generated after the deployment of the `$2x$` bugfix.
    ///
    /// `$2y$` is not "better" or "stronger" than `$2a$` ([`Variant::A`]), but rather a remnant of
    /// one particular buggy implementation of bcrypt (i.e. `crypt_blowfish`).
    Y,
}

impl Variant {
    /// Get the [`Ident`] that corresponds to this bcrypt [`Variant`].
    pub fn ident(&self) -> &Ident {
        match self {
            Variant::Legacy => &BCRYPT_LEGACY,
            Variant::A => &BCRYPT_A,
            Variant::B => &BCRYPT_B,
            Variant::X => &BCRYPT_X,
            Variant::Y => &BCRYPT_Y,
        }
    }

    /// Get the identifier string for this bcrypt [`Variant`].
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
