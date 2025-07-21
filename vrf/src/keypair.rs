//! Cryptographic keypairs for VRF operations.
//!
//! This module defines traits for working with keypairs in the context of
//! Verifiable Random Functions (VRFs). A keypair consists of a proving key
//! (used to generate VRF outputs) and a verifying key (used to verify those
//! outputs).

/// VRF keypair with an associated verifying key.
///
/// Implementors of this trait must provide access to
/// the verifying key, which can be used to validate VRF outputs produced by
/// the proving key.
pub trait Keypair {
    /// This associated type defines the specific type of the verifying key,
    /// which must implement [`Clone`] to allow for safe duplication when
    /// retrieved.
    type VerifyingKey: Clone;

    /// Returns the verifying key.
    fn verifying_key(&self) -> Self::VerifyingKey;
}
