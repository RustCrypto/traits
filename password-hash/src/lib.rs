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
pub type PasswordHashString = phc::PasswordHashString;

use core::{
    fmt::{Debug, Display},
    str::FromStr,
};

/// Numeric version identifier for password hashing algorithms.
pub type Version = u32;

/// Trait for password hashing functions.
///
/// Generic around a password hash to be returned (typically [`PasswordHash`])
pub trait PasswordHasher<H> {
    /// Simple API for computing a [`PasswordHash`] from a password and
    /// salt value.
    ///
    /// Uses the default recommended parameters for a given algorithm.
    fn hash_password(&self, password: &[u8], salt: &[u8]) -> Result<H>;
}

/// Trait for password hashing functions which support customization.
///
/// Generic around a password hash to be returned (typically [`PasswordHash`])
pub trait CustomizedPasswordHasher<H> {
    /// Algorithm-specific parameters.
    type Params: Clone + Debug + Default + Display + FromStr<Err = Error>;

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
}

/// Trait for password verification.
///
/// Generic around a password hash to be returned (typically [`phc::PasswordHash`])
///
/// Automatically impl'd for type that impl [`PasswordHasher`] with [`phc::PasswordHash`] as `H`.
///
/// This trait is object safe and can be used to implement abstractions over
/// multiple password hashing algorithms.
pub trait PasswordVerifier<H> {
    /// Compute this password hashing function against the provided password
    /// using the parameters from the provided password hash and see if the
    /// computed output matches.
    fn verify_password(&self, password: &[u8], hash: &H) -> Result<()>;
}

#[cfg(feature = "phc")]
impl<T: CustomizedPasswordHasher<phc::PasswordHash>> PasswordVerifier<phc::PasswordHash> for T {
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

    /// Verify a password hash in MCF format against the provided password.
    fn verify_mcf_hash(&self, password: &[u8], mcf_hash: &str) -> Result<()>
    where
        Self: PasswordVerifier<phc::PasswordHash>,
    {
        self.verify_password(password, &self.upgrade_mcf_hash(mcf_hash)?)
    }
}
