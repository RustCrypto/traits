//! This crate defines a set of traits which describe the functionality of
//! [password hashing algorithms].
//!
//! Provides a `no_std`-friendly implementation of the
//! [Password Hashing Competition (PHC) string format specification][PHC]
//! (a well-defined subset of the [Modular Crypt Format a.k.a. MCF][MCF]) which
//! works in conjunction with the traits this crate defines.
//!
//! # Supported Crates
//!
//! See [RustCrypto/password-hashes] for algorithm implementations which use
//! this crate for interoperability:
//!
//! - [`argon2`] - Argon2 memory hard key derivation function
//! - [`pbkdf2`] - Password-Based Key Derivation Function v2
//! - [`scrypt`] - scrypt key derivation function
//!
//! # Usage
//!
//! This crate represents password hashes using the [`PasswordHash`] type, which
//! represents a parsed "PHC string" with the following format:
//!
//! ```text
//! $<id>[$v=<version>][$<param>=<value>(,<param>=<value>)*][$<salt>[$<hash>]]
//! ```
//!
//! For more information, please see the documentation for [`PasswordHash`].
//!
//! [password hashing algorithms]: https://en.wikipedia.org/wiki/Cryptographic_hash_function#Password_verification
//! [PHC]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
//! [MCF]: https://passlib.readthedocs.io/en/stable/modular_crypt_format.html
//! [RustCrypto/password-hashes]: https://github.com/RustCrypto/password-hashes
//! [`argon2`]: https://docs.rs/argon2
//! [`pbkdf2`]: https://docs.rs/pbkdf2
//! [`scrypt`]: https://docs.rs/scrypt

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_root_url = "https://docs.rs/password-hash/0.1.3"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(all(feature = "alloc", test))]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod encoding;
mod errors;
mod ident;
mod output;
mod params;
mod salt;
mod value;

pub use crate::{
    encoding::Encoding,
    errors::{B64Error, HashError, HasherError, OutputError, ParamsError, ParseError, VerifyError},
    ident::Ident,
    output::Output,
    params::ParamsString,
    salt::{Salt, SaltString},
    value::{Decimal, Value},
};

use core::{
    convert::{TryFrom, TryInto},
    fmt::{self, Debug},
};

/// Separator character used in password hashes (e.g. `$6$...`).
const PASSWORD_HASH_SEPARATOR: char = '$';

/// Trait for password hashing functions.
pub trait PasswordHasher {
    /// Algorithm-specific parameters.
    type Params: Clone
        + Debug
        + Default
        + for<'a> TryFrom<&'a ParamsString, Error = HasherError>
        + for<'a> TryInto<ParamsString, Error = HasherError>;

    /// Simple API for computing a [`PasswordHash`] from a password and
    /// [`Salt`] value.
    ///
    /// Uses the default recommended parameters for a given algorithm.
    fn hash_password_simple<'a>(
        &self,
        password: &[u8],
        salt: &'a str,
    ) -> Result<PasswordHash<'a>, HasherError> {
        self.hash_password(
            password,
            None,
            None,
            Self::Params::default(),
            salt.try_into()?,
        )
    }

    /// Compute a [`PasswordHash`] with the given algorithm [`Ident`]
    /// (or `None` for the recommended default), password, salt, and
    /// parameters.
    fn hash_password<'a>(
        &self,
        password: &[u8],
        algorithm: Option<Ident<'a>>,
        version: Option<Decimal>,
        params: Self::Params,
        salt: Salt<'a>,
    ) -> Result<PasswordHash<'a>, HasherError>;
}

/// Trait for password verification.
///
/// Automatically impl'd for any type that impls [`PasswordHasher`].
///
/// This trait is object safe and can be used to implement abstractions over
/// multiple password hashing algorithms. One such abstraction is provided by
/// the [`PasswordHash::verify_password`] method.
pub trait PasswordVerifier {
    /// Compute this password hashing function against the provided password
    /// using the parameters from the provided password hash and see if the
    /// computed output matches.
    fn verify_password(&self, password: &[u8], hash: &PasswordHash<'_>) -> Result<(), VerifyError>;
}

impl<T: PasswordHasher> PasswordVerifier for T {
    fn verify_password(&self, password: &[u8], hash: &PasswordHash<'_>) -> Result<(), VerifyError> {
        if let (Some(salt), Some(expected_output)) = (&hash.salt, &hash.hash) {
            let computed_hash = self.hash_password(
                password,
                Some(hash.algorithm),
                hash.version,
                T::Params::try_from(&hash.params)?,
                *salt,
            )?;

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

/// Trait for password hashing algorithms which support the legacy
/// [Modular Crypt Format (MCF)][MCF].
///
/// [MCF]: https://passlib.readthedocs.io/en/stable/modular_crypt_format.html
pub trait McfHasher {
    /// Upgrade an MCF hash to a PHC hash. MCF follow this rough format:
    ///
    /// ```text
    /// $<id>$<content>
    /// ```
    ///
    /// MCF hashes are otherwise largely unstructured and parsed according to
    /// algorithm-specific rules so hashers must parse a raw string themselves.
    fn upgrade_mcf_hash<'a>(&self, hash: &'a str) -> Result<PasswordHash<'a>, HasherError>;

    /// Verify a password hash in MCF format against the provided password.
    fn verify_mcf_hash(&self, password: &[u8], mcf_hash: &str) -> Result<(), VerifyError>
    where
        Self: PasswordVerifier,
    {
        self.verify_password(password, &self.upgrade_mcf_hash(mcf_hash)?)
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
/// $<id>[$v=<version>][$<param>=<value>(,<param>=<value>)*][$<salt>[$<hash>]]
/// ```
///
/// where:
///
/// - `<id>` is the symbolic name for the function
/// - `<version>` is the algorithm version
/// - `<param>` is a parameter name
/// - `<value>` is a parameter value
/// - `<salt>` is an encoding of the salt
/// - `<hash>` is an encoding of the hash output
///
/// The string is then the concatenation, in that order, of:
///
/// - a `$` sign;
/// - the function symbolic name;
/// - optionally, a `$` sign followed by the algorithm version with a `v=version` format;
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

    /// Optional version field.
    ///
    /// This corresponds to the `<version>` field in a PHC string.
    pub version: Option<Decimal>,

    /// Algorithm-specific parameters.
    ///
    /// This corresponds to the set of `$<param>=<value>(,<param>=<value>)*`
    /// name/value pairs in a PHC string.
    pub params: ParamsString,

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
        Self::parse(s, Encoding::B64)
    }

    /// Parse a password hash from the given [`Encoding`].
    pub fn parse(s: &'a str, encoding: Encoding) -> Result<Self, HashError> {
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

        let mut version = None;
        let mut params = ParamsString::new();
        let mut salt = None;
        let mut hash = None;

        let mut next_field = fields.next();

        if let Some(field) = next_field {
            // v=<version>
            if field.starts_with("v=") && !field.contains(params::PARAMS_DELIMITER) {
                version = Some(Value::new(&field[2..]).and_then(|value| value.decimal())?);
                next_field = None;
            }
        }

        if next_field.is_none() {
            next_field = fields.next();
        }

        if let Some(field) = next_field {
            // <param>=<value>
            if field.contains(params::PAIR_DELIMITER) {
                params = field.parse()?;
                next_field = None;
            }
        }

        if next_field.is_none() {
            next_field = fields.next();
        }

        if let Some(s) = next_field {
            salt = Some(s.try_into()?);
        }

        if let Some(field) = fields.next() {
            hash = Some(Output::decode(field, encoding)?);
        }

        if fields.next().is_some() {
            return Err(ParseError::TooLong.into());
        }

        Ok(Self {
            algorithm,
            version,
            params,
            salt,
            hash,
        })
    }

    /// Generate a password hash using the supplied algorithm.
    pub fn generate(
        phf: impl PasswordHasher,
        password: impl AsRef<[u8]>,
        salt: &'a str,
    ) -> Result<Self, HasherError> {
        phf.hash_password_simple(password.as_ref(), salt)
    }

    /// Verify this password hash using the specified set of supported
    /// [`PasswordHasher`] trait objects.
    pub fn verify_password(
        &self,
        phfs: &[&dyn PasswordVerifier],
        password: impl AsRef<[u8]>,
    ) -> Result<(), VerifyError> {
        for &phf in phfs {
            if phf.verify_password(password.as_ref(), self).is_ok() {
                return Ok(());
            }
        }

        Err(VerifyError)
    }

    /// Get the [`Encoding`] that this [`PasswordHash`] is serialized with.
    pub fn encoding(&self) -> Encoding {
        self.hash.map(|h| h.encoding()).unwrap_or_default()
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

        if let Some(version) = self.version {
            write!(f, "{}v={}", PASSWORD_HASH_SEPARATOR, version)?;
        }

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
