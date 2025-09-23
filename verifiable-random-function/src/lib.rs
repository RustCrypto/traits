#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    missing_debug_implementations,
    unused_qualifications
)]

//! # Design
//!
//! Traits are defined to match the functionality of verifiable random functions in
//! [RFC9381](https://www.rfc-editor.org/rfc/rfc9381.pdf).

use digest::{Output, OutputSizeUser};

/// A VRF Proof, denoted `pi` or `pi_string` in RFC9381. See RFC9381 section 1.2 for details.
pub trait Proof
where
{
    /// The hash used to generate the random output.
    type Hash: OutputSizeUser;
    
    /// Get the hash of the VRF proof.
    ///
    /// Defined as `VRF_proof_to_hash` in RFC9381 section 2.
    fn to_hash(&self) -> Output<Self::Hash>;
}

/// A cryptographic object capable of generating VRF proofs.
pub trait Prover<P: Proof>
{

    /// Generate a proof from the given alpha value.
    ///
    /// defined as `VRF_proof` in RFC9381 section 2.
    fn prove(&self, alpha: &[u8]) -> P;
}

/// A cryptographic object capable of verifying VRF proofs.
pub trait Verifier<P: Proof>
{
    /// Verify that the given proof is valid for the given alpha value.
    ///
    /// Defined as `VRF_verify` in RFC9381 section 2.
    fn verify(&self, alpha: &[u8], proof: &P) -> bool;
}
