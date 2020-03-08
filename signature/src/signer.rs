//! Traits for generating digital signatures

#[cfg(feature = "digest-preview")]
use crate::digest::Digest;
use crate::{error::Error, Signature};

/// Sign the provided message bytestring using `Self` (e.g. a cryptographic key
/// or connection to an HSM), returning a digital signature.
pub trait Signer<S: Signature> {
    /// Sign the given message and return a digital signature
    fn sign(&self, msg: &[u8]) -> S {
        self.try_sign(msg).expect("signature operation failed")
    }

    /// Attempt to sign the given message, returning a digital signature on
    /// success, or an error if something went wrong.
    ///
    /// The main intended use case for signing errors is when communicating
    /// with external signers, e.g. cloud KMS, HSMs, or other hardware tokens.
    fn try_sign(&self, msg: &[u8]) -> Result<S, Error>;
}

/// Sign the given prehashed message `Digest` using `Self`.
///
/// This trait is only available when the `digest-preview` cargo feature is
/// enabled.
#[cfg(feature = "digest-preview")]
pub trait DigestSigner<D, S>
where
    D: Digest,
    S: Signature,
{
    /// Sign the given prehashed message `Digest`, returning a signature.
    ///
    /// Panics in the event of a signing error.
    fn sign_digest(&self, digest: D) -> S {
        self.try_sign_digest(digest)
            .expect("signature operation failed")
    }

    /// Attempt to sign the given prehashed message `Digest`, returning a
    /// digital signature on success, or an error if something went wrong.
    fn try_sign_digest(&self, digest: D) -> Result<S, Error>;
}
