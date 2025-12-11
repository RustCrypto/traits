#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    missing_debug_implementations
)]

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

#[cfg(feature = "alloc")]
#[allow(unused_extern_crates)]
extern crate alloc;

mod error;

pub use crate::error::{Error, Result};

#[cfg(feature = "phc")]
pub use phc;

/// DEPRECATED: import this as `password_hash::phc::PasswordHash`.
#[cfg(feature = "phc")]
#[deprecated(
    since = "0.6.0",
    note = "import as `password_hash::phc::PasswordHash` instead"
)]
pub type PasswordHash = phc::PasswordHash;

/// DEPRECATED: use `password_hash::phc::PasswordHash` or `String`
#[cfg(all(feature = "alloc", feature = "phc"))]
#[deprecated(
    since = "0.6.0",
    note = "use `password_hash::phc::PasswordHash` or `String`"
)]
#[allow(deprecated)]
pub type PasswordHashString = phc::PasswordHashString;

use core::{
    fmt::{Debug, Display},
    str::FromStr,
};

/// Numeric version identifier for password hashing algorithms.
pub type Version = u32;

/// Recommended length of a salt: 16-bytes.
///
/// This recommendation comes from the [PHC string format specification]:
///
/// > The role of salts is to achieve uniqueness. A *random* salt is fine
/// > for that as long as its length is sufficient; a 16-byte salt would
/// > work well (by definition, UUID are very good salts, and they encode
/// > over exactly 16 bytes). 16 bytes encode as 22 characters in B64.
///
/// [PHC string format specification]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#function-duties
#[cfg(feature = "getrandom")]
const RECOMMENDED_SALT_LEN: usize = 16;

/// High-level trait for password hashing functions.
///
/// Generic around a password hash to be returned (typically [`phc::PasswordHash`])
pub trait PasswordHasher<H> {
    /// Compute the hash `H` from the given password and salt, potentially using configuration
    /// stored in `&self` for the parameters, or otherwise the recommended defaults.
    ///
    /// The salt should be unique per password. When in doubt, use [`PasswordHasher::hash_password`]
    /// which will choose the salt for you.
    fn hash_password_with_salt(&self, password: &[u8], salt: &[u8]) -> Result<H>;

    /// Compute the hash `H` from the given password, potentially using configuration stored in
    /// `&self` for the parameters, or otherwise the recommended defaults.
    ///
    /// A large random salt will be generated automatically.
    #[cfg(feature = "getrandom")]
    fn hash_password(&self, password: &[u8]) -> Result<H> {
        let mut salt = [0u8; RECOMMENDED_SALT_LEN];
        getrandom::fill(&mut salt).map_err(|_| Error::Crypto)?;
        self.hash_password_with_salt(password, &salt)
    }
}

/// Trait for password hashing functions which support customization.
///
/// Generic around a password hash to be returned (typically [`PasswordHash`])
pub trait CustomizedPasswordHasher<H> {
    /// Algorithm-specific parameters.
    type Params: Clone + Debug + Default + Display + FromStr;

    /// Compute a [`PasswordHash`] from the provided password using an
    /// explicit set of customized algorithm parameters as opposed to the
    /// defaults.
    ///
    /// When in doubt, use [`PasswordHasher::hash_password`] instead.
    fn hash_password_customized(
        &self,
        password: &[u8],
        salt: &[u8],
        algorithm: Option<&str>,
        version: Option<Version>,
        params: Self::Params,
    ) -> Result<H>;

    /// Compute a [`PasswordHash`] using customized parameters only, using the default
    /// algorithm and version.
    fn hash_password_with_params(
        &self,
        password: &[u8],
        salt: &[u8],
        params: Self::Params,
    ) -> Result<H> {
        self.hash_password_customized(password, salt, None, None, params)
    }
}

/// Trait for password verification.
///
/// Generic around a password hash to be returned (typically [`phc::PasswordHash`])
///
/// Automatically impl'd for type that impl [`PasswordHasher`] with [`phc::PasswordHash`] as `H`.
///
/// This trait is object safe and can be used to implement abstractions over
/// multiple password hashing algorithms.
pub trait PasswordVerifier<H: ?Sized> {
    /// Compute this password hashing function against the provided password
    /// using the parameters from the provided password hash and see if the
    /// computed output matches.
    fn verify_password(&self, password: &[u8], hash: &H) -> Result<()>;
}

#[cfg(feature = "phc")]
impl<T: CustomizedPasswordHasher<phc::PasswordHash>, E> PasswordVerifier<phc::PasswordHash> for T
where
    T::Params: FromStr<Err = E>,
    Error: From<E>,
{
    fn verify_password(&self, password: &[u8], hash: &phc::PasswordHash) -> Result<()> {
        #[allow(clippy::single_match)]
        match (&hash.salt, &hash.hash) {
            (Some(salt), Some(expected_output)) => {
                let computed_hash = self.hash_password_customized(
                    password,
                    salt,
                    Some(hash.algorithm.as_str()),
                    hash.version,
                    T::Params::from_str(hash.params.as_str())?,
                )?;

                if let Some(computed_output) = &computed_hash.hash {
                    // See notes on `Output` about the use of a constant-time comparison
                    if expected_output == computed_output {
                        return Ok(());
                    }
                }
            }
            _ => (),
        }

        Err(Error::PasswordInvalid)
    }
}

/// Trait for password hashing algorithms which support the legacy
/// [Modular Crypt Format (MCF)][MCF].
///
/// [MCF]: https://passlib.readthedocs.io/en/stable/modular_crypt_format.html
#[cfg(feature = "phc")]
pub trait McfHasher {
    /// Upgrade an MCF hash to a PHC hash. MCF follow this rough format:
    ///
    /// ```text
    /// $<id>$<content>
    /// ```
    ///
    /// MCF hashes are otherwise largely unstructured and parsed according to
    /// algorithm-specific rules so hashers must parse a raw string themselves.
    fn upgrade_mcf_hash(&self, hash: &str) -> Result<phc::PasswordHash>;
}
