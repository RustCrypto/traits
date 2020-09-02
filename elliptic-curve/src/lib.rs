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
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_root_url = "https://docs.rs/elliptic-curve/0.5.0"
)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod error;
pub mod ops;
pub mod point;
pub mod scalar;
pub mod secret_key;
pub mod util;

#[cfg(feature = "ecdh")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdh")))]
pub mod ecdh;

#[cfg(feature = "weierstrass")]
#[cfg_attr(docsrs, doc(cfg(feature = "weierstrass")))]
pub mod sec1;

#[cfg(feature = "weierstrass")]
#[cfg_attr(docsrs, doc(cfg(feature = "weierstrass")))]
pub mod weierstrass;

pub use self::{error::Error, secret_key::SecretKey};
pub use generic_array::{self, typenum::consts};
pub use subtle;

#[cfg(feature = "digest")]
pub use digest::{self, Digest};

#[cfg(feature = "oid")]
pub use oid;

#[cfg(feature = "rand")]
pub use rand_core;

#[cfg(feature = "zeroize")]
pub use zeroize;

use core::{
    fmt::Debug,
    ops::{Add, Mul},
};
use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};
use subtle::{ConditionallySelectable, ConstantTimeEq, CtOption};

#[cfg(feature = "rand")]
use rand_core::{CryptoRng, RngCore};

/// Byte array containing a serialized scalar value (i.e. an integer)
pub type ElementBytes<C> = GenericArray<u8, <C as Curve>::ElementSize>;

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
        + FromBytes<Size = Self::ElementSize>
        + Into<ElementBytes<Self>>;

    /// Affine point type for a given curve
    type AffinePoint: ConditionallySelectable + Mul<scalar::NonZeroScalar<Self>> + point::Generator;
}

/// Try to decode the given bytes into a curve element
pub trait FromBytes: ConditionallySelectable + Sized {
    /// Size of the serialized byte array
    type Size: ArrayLength<u8>;

    /// Try to decode this object from bytes
    fn from_bytes(bytes: &GenericArray<u8, Self::Size>) -> CtOption<Self>;
}

/// Instantiate this type from the output of a digest.
///
/// This can be used for implementing hash-to-scalar (e.g. as in ECDSA) or
/// hash-to-curve algorithms.
#[cfg(feature = "digest")]
#[cfg_attr(docsrs, doc(cfg(feature = "digest")))]
pub trait FromDigest<C: Curve> {
    /// Instantiate this type from a [`Digest`] instance
    fn from_digest<D>(digest: D) -> Self
    where
        D: Digest<OutputSize = C::ElementSize>;
}

/// Randomly generate a value.
///
/// Primarily intended for use with scalar types for a particular curve.
#[cfg(feature = "rand")]
#[cfg_attr(docsrs, doc(cfg(feature = "rand")))]
pub trait Generate {
    /// Generate a random element of this type using the provided [`CryptoRng`]
    fn generate(rng: impl CryptoRng + RngCore) -> Self;
}

/// Associate an object identifier (OID) with a curve
#[cfg(feature = "oid")]
#[cfg_attr(docsrs, doc(cfg(feature = "oid")))]
pub trait Identifier: Curve {
    /// Object Identifier (OID) for this curve
    const OID: oid::ObjectIdentifier;
}
