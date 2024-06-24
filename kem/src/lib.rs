#![doc = include_str!("../README.md")]
#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_root_url = "https://docs.rs/kem"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, unused_qualifications, missing_debug_implementations)]

use core::fmt::Debug;
use rand_core::CryptoRngCore;

/// A value that can be encapsulated to. Often, this will just be a public key. However, it can
/// also be a bundle of public keys, or it can include a sender's private key for authenticated
/// encapsulation.
pub trait Encapsulate<EK, SS> {
    /// Encapsulation error
    type Error: Debug;

    /// Encapsulates a fresh shared secret
    fn encapsulate(&self, rng: &mut impl CryptoRngCore) -> Result<(EK, SS), Self::Error>;

    /// Encapsulates a fresh shared secret, placing the encapsulated key into the given mut ref.
    /// If this errors, the final value of `encapsulated_key` MUST equal its original value.
    fn encapsulate_in_place(
        &self,
        rng: &mut impl CryptoRngCore,
        encapsulated_key: &mut EK,
    ) -> Result<SS, Self::Error>;
}

/// A value that can be used to decapsulate an encapsulated key. Often, this will just be a secret
/// key. But, as with [`Encapsulate`], it can be a bundle of secret keys, or it can include a
/// sender's private key for authenticated encapsulation.
pub trait Decapsulate<EK, SS> {
    /// Decapsulation error
    type Error: Debug;

    /// Decapsulates the given encapsulated key
    fn decapsulate(&self, encapsulated_key: &EK) -> Result<SS, Self::Error>;
}
