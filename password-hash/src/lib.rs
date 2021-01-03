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

use core::{fmt, str::FromStr};

/// Separator character used in password hashes (e.g. `$6$...`).
const PASSWORD_HASH_SEPARATOR: char = '$';

/// Trait for password hashing functions.
pub trait PasswordHasher {
    /// Compute a [`PasswordHash`] from the given [`Algorithm`] (or the
    /// recommended default), password, salt, and optional [`Params`].
    ///
    /// Use [`Params::new`] or [`Params::default`] to use the default
    /// parameters for a given algorithm.
    fn hash_password(
        &self,
        algorithm: Option<Ident>,
        password: &[u8],
        salt: Salt,
        params: Params,
    ) -> Result<PasswordHash, PhfError>;
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
pub struct PasswordHash {
    /// Password hashing [`Algorithm`].
    ///
    /// This corresponds to the `<id>` field in a PHC string, a.k.a. the
    /// symbolic name for the function.
    pub algorithm: Ident,

    /// Algorithm-specific [`Params`].
    ///
    /// This corresponds to the set of `$<param>=<value>(,<param>=<value>)*`
    /// name/value pairs in a PHC string.
    pub params: Params,

    /// [`Salt`] string for personalizing a password hash output.
    ///
    /// This corresponds to the `<salt>` value in a PHC string.
    pub salt: Option<Salt>,

    /// Password hashing function [`Output`], a.k.a. hash/digest.
    ///
    /// This corresponds to the `<hash>` output in a PHC string.
    pub hash: Option<Output>,
}

impl PasswordHash {
    /// Generate a password hash using the supplied algorithm.
    pub fn generate(
        phf: impl PasswordHasher,
        password: impl AsRef<[u8]>,
        salt: Salt,
        params: Params,
    ) -> Result<Self, PhfError> {
        phf.hash_password(None, password.as_ref(), salt, params)
    }

    /// Verify this password hash using the specified set of supported
    /// [`PasswordHashingFunction`] objects.
    pub fn verify_password(
        &self,
        phfs: &[&dyn PasswordHasher],
        password: impl AsRef<[u8]>,
    ) -> Result<(), VerifyError> {
        if let (Some(salt), Some(expected_hash)) = (&self.salt, &self.hash) {
            for &phf in phfs {
                // TODO(tarcieri): pass in the algorithm?
                if let Ok(PasswordHash {
                    hash: Some(actual_hash),
                    ..
                }) = phf.hash_password(
                    Some(self.algorithm),
                    password.as_ref(),
                    *salt,
                    self.params.clone(),
                ) {
                    // See notes on `Output` about the use of a constant-time comparison
                    if expected_hash == &actual_hash {
                        return Ok(());
                    }
                }
            }
        }

        Err(VerifyError)
    }
}

impl FromStr for PasswordHash {
    type Err = HashError;

    fn from_str(s: &str) -> Result<PasswordHash, HashError> {
        use errors::ParseError;

        if s.is_empty() {
            return Err(ParseError::default().into());
        }

        let mut fields = s.split(PASSWORD_HASH_SEPARATOR);
        let beginning = fields.next().expect("no first field");

        if let Some(first_char) = beginning.chars().next() {
            return Err(ParseError {
                invalid_char: Some(first_char),
                too_long: false,
            }
            .into());
        }

        let algorithm = fields
            .next()
            .ok_or_else(ParseError::default)
            .and_then(Ident::from_str)?;

        let mut params = Params::new();
        let mut salt = None;
        let mut hash = None;

        if let Some(field) = fields.next() {
            if field.contains(params::PAIR_DELIMITER) {
                params = field.parse()?;

                if let Some(s) = fields.next() {
                    salt = Some(s.parse()?);
                }
            } else {
                salt = Some(field.parse()?);
            }
        }

        if let Some(field) = fields.next() {
            hash = Some(field.parse()?);
        }

        if fields.next().is_some() {
            return Err(ParseError::too_long().into());
        }

        Ok(Self {
            algorithm,
            params,
            salt,
            hash,
        })
    }
}

impl fmt::Display for PasswordHash {
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
