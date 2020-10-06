//! RustCrypto: `async-signature` crate.
//!
//! This is an experimental crate containing `async` versions of select traits
//! from the [`signature`] crate, namely [`AsyncSigner`] and when the `digest`
//! feature is enabled, [`AsyncDigestSigner`].
//!
//! Traits are implemented using [`async-trait`], which rewrites the traits to
//! use `Box`-ed futures.
//!
//! The longer-term goal is to move these traits into the [`signature`] crate
//! itself, however before doing so we'd like to remove the [`async-trait`]
//! dependency in order to enable use in `no_std` environments. This crate
//! is a stopgap until that happens.
//!
//! For more information, see:
//! <https://github.com/RustCrypto/traits/issues/304>
//!
//! [`async-trait`]: https://docs.rs/async-trait

#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_root_url = "https://docs.rs/async-signature/0.0.1"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

pub use signature::{self, Error, Signature};

#[cfg(feature = "digest")]
pub use signature::digest::{self, Digest};

use async_trait::async_trait;

/// Asynchronously sign the provided message bytestring using `Self`
/// (e.g. client for a Cloud KMS or HSM), returning a digital signature.
///
/// This trait is an async equivalent of the [`signature::Signer`] trait.
#[async_trait]
pub trait AsyncSigner<S>
where
    Self: Send + Sync,
    S: Signature + Send + 'static,
{
    /// Attempt to sign the given message, returning a digital signature on
    /// success, or an error if something went wrong.
    ///
    /// The main intended use case for signing errors is when communicating
    /// with external signers, e.g. cloud KMS, HSMs, or other hardware tokens.
    async fn sign_async(&self, msg: &[u8]) -> Result<S, Error>;
}

#[async_trait]
impl<S, T> AsyncSigner<S> for T
where
    S: Signature + Send + 'static,
    T: signature::Signer<S> + Send + Sync,
{
    async fn sign_async(&self, msg: &[u8]) -> Result<S, Error> {
        self.try_sign(msg)
    }
}

/// Asynchronously sign the given prehashed message [`Digest`] using `Self`.
///
/// This trait is an async equivalent of the [`signature::DigestSigner`] trait.
#[cfg(feature = "digest")]
#[cfg_attr(docsrs, doc(cfg(feature = "digest")))]
#[async_trait]
pub trait AsyncDigestSigner<D, S>
where
    Self: Send + Sync,
    D: Digest + Send + 'static,
    S: Signature + 'static,
{
    /// Attempt to sign the given prehashed message [`Digest`], returning a
    /// digital signature on success, or an error if something went wrong.
    async fn sign_digest_async(&self, digest: D) -> Result<S, Error>;
}

#[cfg(feature = "digest")]
#[async_trait]
impl<D, S, T> AsyncDigestSigner<D, S> for T
where
    D: Digest + Send + 'static,
    S: Signature + Send + 'static,
    T: signature::DigestSigner<D, S> + Send + Sync,
{
    async fn sign_digest_async(&self, digest: D) -> Result<S, Error> {
        self.try_sign_digest(digest)
    }
}
