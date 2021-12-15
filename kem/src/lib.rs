//! RustCrypto: `kem` crate.
//!
//! Traits which provide generic, object-safe APIs for establishing shared secrets using a key
//! encapsulation mechanism.
//!
//! ## Minimum Supported Rust Version
//!
//! Rust **1.56** or higher.
//!
//! Minimum supported Rust version may be changed in the future, but such changes will be
//! accompanied with a minor version bump.
//!
//! ## SemVer policy
//!
//! - MSRV is considered exempt from SemVer as noted above
//! - All on-by-default features of this library are covered by SemVer
//!
//! # Design
//!
//! This crate provides a common set of traits for non-interactively establishing secrets between
//! peers. This is intended to be implemented by libraries which produce or contain implementations
//! of key encapsulation mechanisms, and used by libraries which want to produce or consume
//! encapsulated secrets while generically supporting any compatible backend.
//!
//! ## Goals
//!
//! The traits provided by this crate were designed with the following goals
//! in mind:
//!
//! - Provide an easy-to-use, misuse resistant API optimized for consumers
//!   (as opposed to implementers) of its traits.
//! - Support common type-safe wrappers around "bag-of-bytes" representations
//!   which can be directly parsed from or written to the "wire".
//! - Allow one provider type to potentially implement support (including being generic over)
//!   several key encapsulation mechanisms.
//! - Keep KEM algorithm customizations / "knobs" out-of-band from the encap/decap APIs, ideally
//!   pushing such concerns into the type system so that algorithm mismatches are caught as type
//!   errors.
//! - Opaque error type which minimizes information leaked from cryptographic failures
//!
//! ## Implementation
//!
//! To accomplish the above goals, the [`Encpsulator`], [`Decapsulator`], and [`AuthDecapsulator`]
//! traits provided by this are generic over an [`EncapsulatedKey`] return value. Notably, they use
//! such a parameter for the return value, allowing it to be inferred by the type checker based on
//! the desired KEM algorithm.
//!
//! The [`Signature`] trait is requires `as_bytes()` and `from_bytes()` methods, enforcing that
//! encapsulated key types are thin wrappers around a "bag-of-bytes" serialization. Inspiration for
//! this approach comes from the Ed25519 signature system, which was based on the observation that
//! past systems were not prescriptive about how signatures should be represented on-the-wire, and
//! that lead to a proliferation of different wire formats and confusion about which ones should be
//! used. This crate aims to provide similar simplicity by minimizing the number of steps involved
//! to obtain a serializable encapsulated key.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_root_url = "https://docs.rs/kem"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, unused_qualifications)]

#[cfg(feature = "std")]
extern crate std;

mod errors;
mod kem;

pub use crate::{errors::*, kem::*};
pub use generic_array;
