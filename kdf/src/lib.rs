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
pub trait Kdf {
    /// Fills `out` with uniformly random data suitable as key material, derived from the input
    /// `secret` and `salt` values, which map to algorithm-specific inputs.
    fn derive_key(&self, secret: &[u8], salt: &[u8], out: &mut [u8]) -> Result<()>;
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
