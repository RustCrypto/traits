//! `PrehashSignature` trait.

/// For intra-doc link resolution.
#[allow(unused_imports)]
use crate::{
    signer::{DigestSigner, Signer},
    verifier::{DigestVerifier, Verifier},
};

/// Marker trait for `Signature` types computable as `𝐒(𝐇(𝒎))`
/// i.e. ones which prehash a message to be signed as `𝐇(𝒎)`
///
/// Where:
///
/// - `𝐒`: signature algorithm
/// - `𝐇`: hash (a.k.a. digest) function
/// - `𝒎`: message
///
/// This approach is relatively common in signature schemes based on the
/// [Fiat-Shamir heuristic].
///
/// [Fiat-Shamir heuristic]: https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic
pub trait PrehashSignature {
    /// Preferred `Digest` algorithm to use when computing this signature type.
    type Digest: digest::Digest;
}
