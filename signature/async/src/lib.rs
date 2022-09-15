#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
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

/// Keypair with async signer component and an associated verifying key.
///
/// This represents a type which holds both an async signing key and a verifying key.
#[deprecated(since = "0.2.1", note = "use signature::Keypair instead")]
pub trait AsyncKeypair<S>: AsRef<Self::VerifyingKey>
where
    S: Signature + Send + 'static,
{
    /// Verifying key type for this keypair.
    type VerifyingKey;

    /// Get the verifying key which can verify signatures produced by the
    /// signing key portion of this keypair.
    fn verifying_key(&self) -> &Self::VerifyingKey {
        self.as_ref()
    }
}

#[allow(deprecated)]
impl<S, T> AsyncKeypair<S> for T
where
    S: Signature + Send + 'static,
    T: signature::Keypair<S> + Send + Sync,
{
    type VerifyingKey = <T as signature::Keypair<S>>::VerifyingKey;
}
