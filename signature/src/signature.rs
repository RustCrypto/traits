//! Signature traits

use crate::error::Error;
use core::fmt::Debug;

/// Trait impl'd by concrete types that represent digital signatures
pub trait Signature: AsRef<[u8]> + Debug + Sized {
    /// Parse a signature from its byte representation
    fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Error>;

    /// Borrow this signature as serialized bytes
    fn as_slice(&self) -> &[u8] {
        self.as_ref()
    }
}

/// Marker trait for `Signature` types computable as `S(H(m))`
///
/// - `S`: signature algorithm
/// - `H`: hash (a.k.a. digest) function
/// - `m`: message
///
/// For signature types that implement this trait, when the `derive-preview`
/// Cargo feature is enabled a custom derive for `Signer` is available for any
/// types that impl `DigestSigner`, and likewise for deriving `Verifier` for
/// types which impl `DigestVerifier`.
#[cfg(feature = "digest")]
pub trait DigestSignature: Signature {
    /// Preferred `Digest` algorithm to use when computing this signature type.
    type Digest: digest::Digest;
}
