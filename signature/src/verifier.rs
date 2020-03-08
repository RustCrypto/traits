//! Trait for verifying digital signatures

#[cfg(feature = "digest-preview")]
use crate::digest::Digest;
use crate::{error::Error, Signature};

/// Verify the provided message bytestring using `Self` (e.g. a public key)
pub trait Verifier<S: Signature> {
    /// Use `Self` to verify that the provided signature for a given message
    /// bytestring is authentic.
    ///
    /// Returns `Error` if it is inauthentic, or otherwise returns `()`.
    fn verify(&self, msg: &[u8], signature: &S) -> Result<(), Error>;
}

/// Verify the provided signature for the given prehashed message `Digest`
/// is authentic.
///
/// This trait is only available when the `digest-preview` cargo feature is
/// enabled.
///
/// It accepts a [`Digest`] instance, as opposed to a raw digest byte array,
/// as the security of signature algorithms built on hash functions often
/// depends critically on the input being a random oracle as opposed to a
/// value an attacker can choose and solve for. This is enforced at the API
/// level by taking a [`Digest`] instance in order to better resist misuse.
#[cfg(feature = "digest-preview")]
pub trait DigestVerifier<D, S>
where
    D: Digest,
    S: Signature,
{
    /// Verify the signature against the given `Digest` output.
    fn verify_digest(&self, digest: D, signature: &S) -> Result<(), Error>;
}
