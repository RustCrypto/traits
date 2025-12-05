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
extern crate alloc;

#[cfg(feature = "rand_core")]
pub use rand_core;

pub mod errors;
pub mod phc;

pub use crate::errors::{Error, Result};
pub use phc::PasswordHash;

#[cfg(feature = "alloc")]
pub use phc::PasswordHashString;

use crate::phc::ParamsString;
use core::fmt::Debug;

/// Numeric version identifier for password hashing algorithms.
pub type Version = u32;

/// Trait for password hashing functions.
pub trait PasswordHasher {
    /// Simple API for computing a [`PasswordHash`] from a password and
    /// salt value.
    ///
    /// Uses the default recommended parameters for a given algorithm.
    fn hash_password<'a>(&self, password: &[u8], salt: &'a str) -> Result<PasswordHash<'a>>;
}

/// Trait for password hashing functions which support customization.
pub trait CustomizedPasswordHasher {
    /// Algorithm-specific parameters.
    type Params: Clone
        + Debug
        + Default
        + for<'a> TryFrom<&'a PasswordHash<'a>, Error = Error>
        + TryInto<ParamsString, Error = Error>;

    /// Compute a [`PasswordHash`] from the provided password using an
    /// explicit set of customized algorithm parameters as opposed to the
    /// defaults.
    ///
    /// When in doubt, use [`PasswordHasher::hash_password`] instead.
    fn hash_password_customized<'a>(
        &self,
        password: &[u8],
        algorithm: Option<&'a str>,
        version: Option<Version>,
        params: Self::Params,
        salt: &'a str,
    ) -> Result<PasswordHash<'a>>;
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
    fn verify_password(&self, password: &[u8], hash: &PasswordHash<'_>) -> Result<()>;
}

impl<T: CustomizedPasswordHasher> PasswordVerifier for T {
    fn verify_password(&self, password: &[u8], hash: &PasswordHash<'_>) -> Result<()> {
        if let (Some(salt), Some(expected_output)) = (&hash.salt, &hash.hash) {
            let computed_hash = self.hash_password_customized(
                password,
                Some(hash.algorithm.as_str()),
                hash.version,
                T::Params::try_from(hash)?,
                salt.as_str(),
            )?;

            if let Some(computed_output) = &computed_hash.hash {
                // See notes on `Output` about the use of a constant-time comparison
                if expected_output == computed_output {
                    return Ok(());
                }
            }
        }

        Err(Error::Password)
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
    fn upgrade_mcf_hash<'a>(&self, hash: &'a str) -> Result<PasswordHash<'a>>;

    /// Verify a password hash in MCF format against the provided password.
    fn verify_mcf_hash(&self, password: &[u8], mcf_hash: &str) -> Result<()>
    where
        Self: PasswordVerifier,
    {
        self.verify_password(password, &self.upgrade_mcf_hash(mcf_hash)?)
    }
}
