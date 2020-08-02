//! General purpose Elliptic Curve Cryptography (ECC) support, including types
//! and traits for representing various elliptic curve forms, scalars, points,
//! and public/secret keys composed thereof.
//!
//! ## Minimum Supported Rust Version
//!
//! Rust **1.41** or higher.
//!
//! Minimum supported Rust version can be changed in the future, but it will be
//! done with a minor version bump.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png",
    html_root_url = "https://docs.rs/elliptic-curve/0.4.0"
)]

#[cfg(feature = "std")]
extern crate std;

pub mod error;
pub mod oid;
pub mod ops;
pub mod point;
pub mod scalar;
pub mod secret_key;

// TODO(tarcieri): other curve forms
#[cfg(feature = "weierstrass")]
#[cfg_attr(docsrs, doc(cfg(feature = "weierstrass")))]
pub mod weierstrass;

pub use self::{error::Error, oid::ObjectIdentifier, secret_key::SecretKey};
pub use generic_array::{self, typenum::consts};
pub use subtle;

#[cfg(feature = "rand_core")]
pub use rand_core;

#[cfg(feature = "zeroize")]
pub use zeroize;

use core::{
    fmt::Debug,
    ops::{Add, Mul},
};
use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};
use subtle::{ConditionallySelectable, ConstantTimeEq};

#[cfg(feature = "rand_core")]
use rand_core::{CryptoRng, RngCore};

/// Elliptic curve.
///
/// This trait is intended to be impl'd by a ZST which represents a concrete
/// elliptic curve.
///
/// Other traits in this crate which are bounded by [`Curve`] are intended to
/// be impl'd by these ZSTs, facilitating types which are generic over elliptic
/// curves (e.g. [`SecretKey`]).
pub trait Curve: Clone + Debug + Default + Eq + Ord + Send + Sync {
    /// Number of bytes required to serialize elements of field elements
    /// associated with this curve, e.g. elements of the base/scalar fields.
    ///
    /// This is used for computing the sizes for types related to this curve.
    type ElementSize: ArrayLength<u8> + Add + Eq + Ord + Unsigned;
}

/// Elliptic curve with curve arithmetic support
pub trait Arithmetic: Curve {
    /// Scalar type for a given curve
    type Scalar: ConditionallySelectable
        + ConstantTimeEq
        + Default
        + secret_key::FromSecretKey<Self>;

    /// Affine point type for a given curve
    type AffinePoint: ConditionallySelectable + Mul<scalar::NonZeroScalar<Self>> + point::Generator;
}

/// Associate an object identifier (OID) with a curve
pub trait Identifier: Curve {
    /// Object Identifier (OID) for this curve
    const OID: ObjectIdentifier;
}

/// Randomly generate a value.
///
/// Primarily intended for use with scalar types for a particular curve.
#[cfg(feature = "rand_core")]
#[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
pub trait Generate {
    /// Generate a random element of this type using the provided [`CryptoRng`]
    fn generate(rng: impl CryptoRng + RngCore) -> Self;
}

/// Byte array containing a serialized scalar value (i.e. an integer)
pub type ScalarBytes<C> = GenericArray<u8, <C as Curve>::ElementSize>;
