#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    unused_qualifications,
    missing_debug_implementations
)]

pub use signature::{self, Error};

#[cfg(feature = "digest")]
pub use signature::digest::{self, Digest};

#[cfg(feature = "rand_core")]
use signature::rand_core::CryptoRngCore;

/// Asynchronously sign the provided message bytestring using `Self`
/// (e.g. client for a Cloud KMS or HSM), returning a digital signature.
///
/// This trait is an async equivalent of the [`signature::Signer`] trait.
#[allow(async_fn_in_trait)]
pub trait AsyncSigner<S> {
    /// Attempt to sign the given message, returning a digital signature on
    /// success, or an error if something went wrong.
    ///
    /// The main intended use case for signing errors is when communicating
    /// with external signers, e.g. cloud KMS, HSMs, or other hardware tokens.
    async fn sign_async(&self, msg: &[u8]) -> Result<S, Error>;
}

impl<S, T> AsyncSigner<S> for T
where
    T: signature::Signer<S>,
{
    async fn sign_async(&self, msg: &[u8]) -> Result<S, Error> {
        self.try_sign(msg)
    }
}

/// Asynchronously sign the given prehashed message [`Digest`] using `Self`.
///
/// This trait is an async equivalent of the [`signature::DigestSigner`] trait.
#[cfg(feature = "digest")]
#[allow(async_fn_in_trait)]
pub trait AsyncDigestSigner<D, S>
where
    D: Digest,
{
    /// Attempt to sign the given prehashed message [`Digest`], returning a
    /// digital signature on success, or an error if something went wrong.
    async fn sign_digest_async(&self, digest: D) -> Result<S, Error>;
}

/// Sign the given message using the provided external randomness source.
#[cfg(feature = "rand_core")]
#[allow(async_fn_in_trait)]
pub trait AsyncRandomizedSigner<S> {
    /// Sign the given message and return a digital signature
    async fn sign_with_rng_async(&self, rng: &mut impl CryptoRngCore, msg: &[u8]) -> S {
        self.try_sign_with_rng_async(rng, msg)
            .await
            .expect("signature operation failed")
    }

    /// Attempt to sign the given message, returning a digital signature on
    /// success, or an error if something went wrong.
    ///
    /// The main intended use case for signing errors is when communicating
    /// with external signers, e.g. cloud KMS, HSMs, or other hardware tokens.
    async fn try_sign_with_rng_async(
        &self,
        rng: &mut impl CryptoRngCore,
        msg: &[u8],
    ) -> Result<S, Error>;
}

#[cfg(feature = "rand_core")]
impl<S, T> AsyncRandomizedSigner<S> for T
where
    T: signature::RandomizedSigner<S>,
{
    async fn try_sign_with_rng_async(
        &self,
        rng: &mut impl CryptoRngCore,
        msg: &[u8],
    ) -> Result<S, Error> {
        self.try_sign_with_rng(rng, msg)
    }
}
