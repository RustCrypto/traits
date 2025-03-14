//! Verifiable Random Function (VRF) traits
//!
//! This module defines core traits for implementing Verifiable Random Functions.
//! A VRF allows a prover to generate an unforgeable proof for a value that can be
//! verified by anyone who has the corresponding verification key.
//!
//! The three main traits defined here are:
//! - [`Proof`]: Represents a VRF proof that can be converted to a hash output
//! - [`Prover`]: Represents VRF proof generator
//! - [`Verifier`]: Represents VRF proof verifier

#![no_std]

mod error;
mod keypair;

use digest::{Output, OutputSizeUser};

/// VRF proof representation.
///
/// This trait defines the interface for VRF proofs. Proofs can be transformed
/// into hash outputs of a specific hash algorithm `H`.
pub trait Proof<H>
where
    H: OutputSizeUser,
{
    /// Converts a proof to its corresponding hash output.
    fn proof_to_hash(&self) -> Output<H>;
}

/// VRF prover.
///
/// Implementers of this trait can generate verifiable random function proofs
/// for arbitrary input challenges. The prover uses secret key to
/// produce outputs that can later be verified by parties with the corresponding
/// verification key.
pub trait Prover<H>
where
    H: OutputSizeUser,
{
    /// The specific proof type produced by this prover.
    type Proof: Proof<H>;

    /// Generates a VRF proof for the given input challenge.
    ///
    /// # Parameters
    /// * `alpha` - The input challenge/message bytes for which to generate a proof
    ///
    /// # Returns
    /// A Result containing either the generated proof or an error if proof generation fails.
    fn prove(&self, alpha: &[u8]) -> error::Result<Self::Proof>;
}

/// VRF verifier.
///
/// Implementers of this trait can verify VRF proofs for the given input.
pub trait Verifier<H>
where
    H: OutputSizeUser,
{
    /// The specific proof type this verifier can check.
    type Proof: Proof<H>;

    /// Verifies a VRF proof for an input challenge.
    ///
    /// # Parameters
    /// * `alpha` - The original input challenge/message bytes
    /// * `proof` - The proof to verify
    ///
    /// # Returns
    /// A Result containing either the hash output (if verification succeeds) or an error.
    fn verify(&self, alpha: &[u8], proof: Self::Proof) -> error::Result<Output<H>>;
}
