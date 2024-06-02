#![allow(dead_code)]
//! Check compilation of the various traits exposed by async_signature.
//!
//! This is intended to make sure we can implement those traits without conflict from a blanket
//! implementation.

use async_signature::{AsyncSigner, Error};

struct Signature;

struct MockSigner;

impl AsyncSigner<Signature> for MockSigner {
    async fn sign_async(&self, _msg: &[u8]) -> Result<Signature, Error> {
        unimplemented!("just meant to check compilation")
    }
}

#[cfg(feature = "digest")]
impl<D> async_signature::AsyncDigestSigner<D, Signature> for MockSigner
where
    D: async_signature::Digest,
{
    async fn sign_digest_async(&self, _digest: D) -> Result<Signature, Error> {
        unimplemented!("just meant to check compilation")
    }
}

#[cfg(feature = "rand_core")]
impl async_signature::AsyncRandomizedSigner<Signature> for MockSigner {
    async fn try_sign_with_rng_async(
        &self,
        _rng: &mut impl async_signature::signature::rand_core::CryptoRngCore,
        _msg: &[u8],
    ) -> Result<Signature, Error> {
        unimplemented!("just meant to check compilation")
    }
}
