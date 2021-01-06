//! This crate defines a set of traits which describe the functionality of
//! [password hashing algorithms].
//!
//! Provides a `no_std`-friendly implementation of the [PHC string format specification]
//! (a well-defined subset of the [Modular Crypt Format a.k.a. MCF][MCF]) which
//! works in conjunction with the traits this crate defines.
//!
//! See [RustCrypto/password-hashes] for algorithm implementations which use
//! this crate for interoperability.
//!
//! # Usage
//!
//! This crate represents password hashes using the [`PasswordHash`] type, which
//! represents a parsed "PHC string" with the following format:
//!
//! ```text
//! $<id>[$<param>=<value>(,<param>=<value>)*][$<salt>[$<hash>]]
//! ```
//!
//! For more information, please see the documentation for [`PasswordHash`].
//!
//! [password hashing algorithms]: https://en.wikipedia.org/wiki/Cryptographic_hash_function#Password_verification
//! [PHC string format specification]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
//! [MCF]: https://passlib.readthedocs.io/en/stable/modular_crypt_format.html
//! [RustCrypto/password-hashes]: https://github.com/RustCrypto/password-hashes

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![allow(clippy::len_without_is_empty)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod b64;
pub mod errors;
pub mod params;

mod ident;
mod output;
mod salt;

pub use crate::{
    errors::{HashError, PhfError, VerifyError},
    ident::Ident,
    output::Output,
    params::Params,
    salt::Salt,
};

use core::{
    convert::{TryFrom, TryInto},
    fmt,
};

/// Separator character used in password hashes (e.g. `$6$...`).
const PASSWORD_HASH_SEPARATOR: char = '$';

/// Trait for password hashing functions.
pub trait PasswordHasher {
    /// Compute a [`PasswordHash`] with the given algorithm [`Ident`]
    /// (or `None` for the recommended default), password, salt, and optional
    /// [`Params`].
    ///
    /// Use [`Params::new`] or [`Params::default`] to use the default
    /// parameters for a given algorithm.
    fn hash_password<'a>(
        &self,
        algorithm: Option<Ident<'a>>,
        password: &[u8],
        salt: Salt<'a>,
        params: Params<'a>,
    ) -> Result<PasswordHash<'a>, PhfError>;

    /// Compute this password hashing function against the provided password
    /// using the parameters from the provided password hash and see if the
    /// computed output matches.
    fn verify_password(&self, password: &[u8], hash: &PasswordHash<'_>) -> Result<(), VerifyError> {
        if let (Some(salt), Some(expected_output)) = (&hash.salt, &hash.hash) {
            let computed_hash =
                self.hash_password(Some(hash.algorithm), password, *salt, hash.params.clone())?;

            if let Some(computed_output) = &computed_hash.hash {
                // See notes on `Output` about the use of a constant-time comparison
                if expected_output == computed_output {
                    return Ok(());
                }
            }
        }

        Err(VerifyError)
    }
}

/// Password hash.
///
/// This type corresponds to the parsed representation of a PHC string as
/// described in the [PHC string format specification][1].
///
/// PHC strings have the following format:
///
/// ```text
/// $<id>[$<param>=<value>(,<param>=<value>)*][$<salt>[$<hash>]]
/// ```
///
/// where:
///
/// - `<id>` is the symbolic name for the function
/// - `<param>` is a parameter name
/// - `<value>` is a parameter value
/// - `<salt>` is an encoding of the salt
/// - `<hash>` is an encoding of the hash output
///
/// The string is then the concatenation, in that order, of:
///
/// - a `$` sign;
/// - the function symbolic name;
/// - optionally, a `$` sign followed by one or several parameters, each with a `name=value` format;
///   the parameters are separated by commas;
/// - optionally, a `$` sign followed by the (encoded) salt value;
/// - optionally, a `$` sign followed by the (encoded) hash output (the hash output may be present
///   only if the salt is present).
///
/// [1]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#specification
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordHash<'a> {
    /// Password hashing algorithm identifier.
    ///
    /// This corresponds to the `<id>` field in a PHC string, a.k.a. the
    /// symbolic name for the function.
    pub algorithm: Ident<'a>,

    /// Algorithm-specific [`Params`].
    ///
    /// This corresponds to the set of `$<param>=<value>(,<param>=<value>)*`
    /// name/value pairs in a PHC string.
    pub params: Params<'a>,

    /// [`Salt`] string for personalizing a password hash output.
    ///
    /// This corresponds to the `<salt>` value in a PHC string.
    pub salt: Option<Salt<'a>>,

    /// Password hashing function [`Output`], a.k.a. hash/digest.
    ///
    /// This corresponds to the `<hash>` output in a PHC string.
    pub hash: Option<Output>,
}

impl<'a> PasswordHash<'a> {
    /// Parse a password hash from a string in the PHC string format.
    pub fn new(s: &'a str) -> Result<Self, HashError> {
        use errors::ParseError;

        if s.is_empty() {
            return Err(ParseError::Empty.into());
        }

        let mut fields = s.split(PASSWORD_HASH_SEPARATOR);
        let beginning = fields.next().expect("no first field");

        if let Some(first_char) = beginning.chars().next() {
            return Err(ParseError::InvalidChar(first_char).into());
        }

        let algorithm = fields
            .next()
            .ok_or(ParseError::TooShort)
            .and_then(Ident::try_from)?;

        let mut params = Params::new();
        let mut salt = None;
        let mut hash = None;

        if let Some(field) = fields.next() {
            if field.contains(params::PAIR_DELIMITER) {
                params = Params::try_from(field)?;

                if let Some(s) = fields.next() {
                    salt = Some(s.try_into()?);
                }
            } else {
                salt = Some(field.try_into()?);
            }
        }

        if let Some(field) = fields.next() {
            hash = Some(field.parse()?);
        }

        if fields.next().is_some() {
            return Err(ParseError::TooLong.into());
        }

        Ok(Self {
            algorithm,
            params,
            salt,
            hash,
        })
    }

    /// Generate a password hash using the supplied algorithm.
    pub fn generate(
        phf: impl PasswordHasher,
        password: impl AsRef<[u8]>,
        salt: Salt<'a>,
        params: Params<'a>,
    ) -> Result<Self, PhfError> {
        phf.hash_password(None, password.as_ref(), salt, params)
    }

    /// Verify this password hash using the specified set of supported
    /// [`PasswordHasher`] trait objects.
    pub fn verify_password(
        &self,
        phfs: &[&dyn PasswordHasher],
        password: impl AsRef<[u8]>,
    ) -> Result<(), VerifyError> {
        for &phf in phfs {
            if phf.verify_password(password.as_ref(), self).is_ok() {
                return Ok(());
            }
        }

        Err(VerifyError)
    }
}

// Note: this uses `TryFrom` instead of `FromStr` to support a lifetime on
// the `str` the value is being parsed from.
impl<'a> TryFrom<&'a str> for PasswordHash<'a> {
    type Error = HashError;

    fn try_from(s: &'a str) -> Result<Self, HashError> {
        Self::new(s)
    }
}

impl<'a> fmt::Display for PasswordHash<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", PASSWORD_HASH_SEPARATOR, self.algorithm)?;

        if !self.params.is_empty() {
            write!(f, "{}{}", PASSWORD_HASH_SEPARATOR, self.params)?;
        }

        if let Some(salt) = &self.salt {
            write!(f, "{}{}", PASSWORD_HASH_SEPARATOR, salt)?;
        }

        if let Some(hash) = &self.hash {
            write!(f, "{}{}", PASSWORD_HASH_SEPARATOR, hash)?;
        }

        Ok(())
    }
}
