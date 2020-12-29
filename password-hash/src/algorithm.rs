//! Password hashing algorithms.
//!
//! This module defines an [`Algorithm`] enum representing password hashing
//! algorithms.
//!
//! # `registry` feature
//!
//! When the `registry` crate feature is enabled (which it is by default),
//! this module defines a registry of well-known password hashing algorithms.
//!
//! Each has an [`Ident`] constant, and the [`Algorithm`] enum can be used to
//! discriminate between them.
//!

#[cfg(feature = "registry")]
#[cfg_attr(docsrs, doc(cfg(feature = "registry")))]
pub mod argon2;

#[cfg(feature = "registry")]
#[cfg_attr(docsrs, doc(cfg(feature = "registry")))]
pub mod bcrypt;

#[cfg(feature = "registry")]
#[cfg_attr(docsrs, doc(cfg(feature = "registry")))]
pub mod pbkdf2;

#[cfg(feature = "registry")]
#[cfg_attr(docsrs, doc(cfg(feature = "registry")))]
pub mod shacrypt;

use crate::{errors::ParseError, Ident};
use core::{fmt, str::FromStr};

/// MD5 crypt
///
/// <https://www.usenix.org/legacy/publications/library/proceedings/usenix99/full_papers/provos/provos_html/node10.html>
#[cfg(feature = "registry")]
#[cfg_attr(docsrs, doc(cfg(feature = "registry")))]
pub const MD5_CRYPT: Ident = Ident::new("1");

/// scrypt
///
/// <https://en.wikipedia.org/wiki/Scrypt>
#[cfg(feature = "registry")]
#[cfg_attr(docsrs, doc(cfg(feature = "registry")))]
pub const SCRYPT: Ident = Ident::new("scrypt");

/// Password hashing algorithms.
///
/// Includes variants for well-known password hashing algorithms, as well as
/// a catch-all [`Algorithm::Other`] variant for unknown algorithms.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Algorithm {
    /// [Argon2][`argon2`]
    ///
    /// <https://en.wikipedia.org/wiki/Argon2>
    #[cfg(feature = "registry")]
    #[cfg_attr(docsrs, doc(cfg(feature = "registry")))]
    Argon2(argon2::Variant),

    /// [bcrypt]
    ///
    /// <https://en.wikipedia.org/wiki/Bcrypt>
    #[cfg(feature = "registry")]
    #[cfg_attr(docsrs, doc(cfg(feature = "registry")))]
    Bcrypt(bcrypt::Variant),

    /// MD5 crypt
    ///
    /// <https://www.usenix.org/legacy/publications/library/proceedings/usenix99/full_papers/provos/provos_html/node10.html>
    #[cfg(feature = "registry")]
    #[cfg_attr(docsrs, doc(cfg(feature = "registry")))]
    Md5Crypt,

    /// [PBKDF2][`pbkdf2`]
    ///
    /// <https://en.wikipedia.org/wiki/PBKDF2>
    #[cfg(feature = "registry")]
    #[cfg_attr(docsrs, doc(cfg(feature = "registry")))]
    Pbkdf2(pbkdf2::Variant),

    /// scrypt
    ///
    /// <https://en.wikipedia.org/wiki/Scrypt>
    #[cfg(feature = "registry")]
    #[cfg_attr(docsrs, doc(cfg(feature = "registry")))]
    Scrypt,

    /// [`SHA-crypt`][`shacrypt`]
    ///
    /// <https://www.akkadia.org/drepper/SHA-crypt.txt>
    #[cfg(feature = "registry")]
    #[cfg_attr(docsrs, doc(cfg(feature = "registry")))]
    ShaCrypt(shacrypt::Variant),

    /// Password hashing algorithms with unrecognized algorithm identifiers
    Other(Ident),
}

impl Algorithm {
    /// Get the [`Ident`] that corresponds to this [`Algorithm`].
    #[cfg(not(feature = "registry"))]
    pub fn ident(&self) -> &Ident {
        let Algorithm::Other(ident) = self;
        ident
    }

    /// Get the [`Ident`] that corresponds to this [`Algorithm`].
    #[cfg(feature = "registry")]
    pub fn ident(&self) -> &Ident {
        match self {
            Algorithm::Argon2(variant) => variant.ident(),
            Algorithm::Bcrypt(variant) => variant.ident(),
            Algorithm::Md5Crypt => &MD5_CRYPT,
            Algorithm::Pbkdf2(variant) => variant.ident(),
            Algorithm::Scrypt => &SCRYPT,
            Algorithm::ShaCrypt(variant) => variant.ident(),
            Algorithm::Other(other) => other,
        }
    }

    /// Get the identifier string for this [`Algorithm`]
    pub fn as_str(&self) -> &str {
        self.ident().as_ref()
    }
}

impl AsRef<str> for Algorithm {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[cfg(not(feature = "registry"))]
impl From<Ident> for Algorithm {
    fn from(ident: Ident) -> Algorithm {
        Algorithm::Other(ident)
    }
}

#[cfg(feature = "registry")]
impl From<Ident> for Algorithm {
    fn from(ident: Ident) -> Algorithm {
        match ident {
            argon2::ARGON2D => Algorithm::Argon2(argon2::Variant::D),
            argon2::ARGON2I => Algorithm::Argon2(argon2::Variant::I),
            argon2::ARGON2ID => Algorithm::Argon2(argon2::Variant::ID),
            bcrypt::BCRYPT_LEGACY => Algorithm::Bcrypt(bcrypt::Variant::Legacy),
            bcrypt::BCRYPT_A => Algorithm::Bcrypt(bcrypt::Variant::A),
            bcrypt::BCRYPT_B => Algorithm::Bcrypt(bcrypt::Variant::B),
            bcrypt::BCRYPT_X => Algorithm::Bcrypt(bcrypt::Variant::X),
            bcrypt::BCRYPT_Y => Algorithm::Bcrypt(bcrypt::Variant::Y),
            MD5_CRYPT => Algorithm::Md5Crypt,
            pbkdf2::PBKDF2_SHA1 => Algorithm::Pbkdf2(pbkdf2::Variant::Sha1),
            pbkdf2::PBKDF2_SHA256 => Algorithm::Pbkdf2(pbkdf2::Variant::Sha256),
            pbkdf2::PBKDF2_SHA512 => Algorithm::Pbkdf2(pbkdf2::Variant::Sha512),
            SCRYPT => Algorithm::Scrypt,
            shacrypt::SHACRYPT_SHA256 => Algorithm::ShaCrypt(shacrypt::Variant::Sha256),
            shacrypt::SHACRYPT_SHA512 => Algorithm::ShaCrypt(shacrypt::Variant::Sha512),
            _ => Algorithm::Other(ident),
        }
    }
}

impl From<Algorithm> for Ident {
    fn from(alg: Algorithm) -> Ident {
        *alg.ident()
    }
}

impl FromStr for Algorithm {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Algorithm, ParseError> {
        s.parse::<Ident>().map(Into::into)
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
