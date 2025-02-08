//! Hazardous Materials: low-level APIs which can be insecure if misused.
//!
//! The traits in this module are not generally recommended, and should only be
//! used in special cases where they are specifically needed.
//!
//! Using them incorrectly can introduce security vulnerabilities. Please
//! carefully read the documentation before attempting to use them.

use signature::Error;

#[cfg(feature = "rand_core")]
use signature::rand_core::CryptoRngCore;

/// Asynchronously sign the provided message prehash, returning a digital signature.
#[allow(async_fn_in_trait)]
pub trait AsyncPrehashSigner<S> {
    /// Attempt to sign the given message digest, returning a digital signature
    /// on success, or an error if something went wrong.
    ///
    /// The `prehash` parameter should be the output of a secure cryptographic
    /// hash function.
    ///
    /// This API takes a `prehash` byte slice as there can potentially be many
    /// compatible lengths for the message digest for a given concrete signature
    /// algorithm.
    ///
    /// Allowed lengths are algorithm-dependent and up to a particular
    /// implementation to decide.
    async fn sign_prehash_async(&self, prehash: &[u8]) -> Result<S, Error>;
}

/// Asynchronously sign the provided message prehash using the provided external randomness source, returning a digital signature.
#[cfg(feature = "rand_core")]
#[allow(async_fn_in_trait)]
pub trait AsyncRandomizedPrehashSigner<S> {
    /// Attempt to sign the given message digest, returning a digital signature
    /// on success, or an error if something went wrong.
    ///
    /// The `prehash` parameter should be the output of a secure cryptographic
    /// hash function.
    ///
    /// This API takes a `prehash` byte slice as there can potentially be many
    /// compatible lengths for the message digest for a given concrete signature
    /// algorithm.
    ///
    /// Allowed lengths are algorithm-dependent and up to a particular
    /// implementation to decide.
    async fn sign_prehash_with_rng_async(
        &self,
        rng: &mut impl CryptoRngCore,
        prehash: &[u8],
    ) -> Result<S, Error>;
}
