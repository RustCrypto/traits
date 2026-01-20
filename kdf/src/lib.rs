#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, unused_qualifications)]

use core::fmt;

/// Key Derivation Function.
///
/// These functions deterministically produce uniformly random outputs suitable as key material.
///
/// It is recommended for types which impls this trait to also impl [`Default`] whenever possible.
pub trait Kdf {
    /// Writes uniformly random data suitable as key material into the entire length of `out`,
    /// derived from the following inputs:
    ///
    /// - `secret`: this is typically a high-entropy input with at least 128-bits of symmetric
    ///   strength/randomness, but does not have to be uniformly random (e.g. can be the output of
    ///   a Diffie-Hellman exchange). For KDFs marked [`Pbkdf`], this parameter is allowed to be a
    ///   password with a lower entropy, but consumers of these traits MUST bound on [`Pbkdf`]
    ///   whenever they are expecting the input to be a password.
    /// - `non_secret`: this value customizes/personalizes the output and can be used to generate
    ///   multiple unrelated outputs from the same input. Its secrecy is irrelevant, and it can be
    ///   published to the world if desired. It maps to an algorithm specific parameter which
    ///   accomplishes this purpose, sometimes called "salt", "info", "context", or "customization".
    ///   See algorithm-specific documentation for the specific input this maps to for the specific
    ///   impls for a given algorithm. For KDFs marked [`Pbkdf`] this is always the salt.
    fn derive_key(&self, secret: &[u8], non_secret: &[u8], out: &mut [u8]) -> Result<()>;
}

/// Password-Based Key Derivation Functions: KDFs where it's suitable for the input `secret` to be
/// a user-specified password, which employ algorithms designed to be resistant to brute-force
/// attacks.
pub trait Pbkdf: Kdf {}

/// Key derivation errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KDF error")
    }
}

impl core::error::Error for Error {}

/// Result type with the `kdf` crate's [`Error`].
pub type Result<T> = core::result::Result<T, Error>;
