//! General purpose Elliptic Curve Cryptography (ECC) support, including types
//! and traits for representing various elliptic curve forms, scalars, points,
//! and public/secret keys composed thereof.
//!
//! ## Minimum Supported Rust Version
//!
//! Rust **1.44** or higher.
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
    html_root_url = "https://docs.rs/elliptic-curve/0.6.6"
)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod error;
pub mod ops;
pub mod sec1;
pub mod util;
pub mod weierstrass;

#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub mod point;
#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub mod scalar;

#[cfg(feature = "ecdh")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdh")))]
pub mod ecdh;

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
pub mod secret_key;

pub use self::error::Error;

pub use generic_array::{self, typenum::consts};
pub use rand_core;
pub use subtle;

#[cfg(feature = "arithmetic")]
pub use self::{
    point::{AffinePoint, ProjectiveArithmetic, ProjectivePoint},
    scalar::Scalar,
};
#[cfg(feature = "arithmetic")]
pub use bitvec::view::BitView; // TODO: https://github.com/zkcrypto/ff/pull/40
#[cfg(feature = "arithmetic")]
pub use ff::{self, Field};
#[cfg(feature = "arithmetic")]
pub use group::{self, Group};

#[cfg(feature = "digest")]
pub use digest::{self, Digest};

#[cfg(feature = "oid")]
pub use oid;

#[cfg(feature = "zeroize")]
pub use secret_key::SecretKey;
#[cfg(feature = "zeroize")]
pub use zeroize;

use core::{fmt::Debug, ops::Add};
use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};

/// Elliptic curve.
///
/// This trait is intended to be impl'd by a ZST which represents a concrete
/// elliptic curve.
///
/// Other traits in this crate which are bounded by [`Curve`] are intended to
/// be impl'd by these ZSTs, facilitating types which are generic over elliptic
/// curves (e.g. [`SecretKey`]).
pub trait Curve: Clone + Debug + Default + Eq + Ord + Send + Sync {
    /// Size of this curve's field in *bytes*, i.e. the number of bytes needed
    /// to serialize a field element.
    ///
    /// This is used for computing the sizes of field element types related to
    /// this curve and other types composed from them (e.g. signatures).
    type FieldSize: ArrayLength<u8> + Add + Eq + Ord + Unsigned;
}

/// Byte representation of a base/scalar field element of a given curve.
pub type FieldBytes<C> = GenericArray<u8, <C as Curve>::FieldSize>;

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
        D: Digest<OutputSize = C::FieldSize>;
}

/// Associate an object identifier (OID) with a curve
#[cfg(feature = "oid")]
#[cfg_attr(docsrs, doc(cfg(feature = "oid")))]
pub trait Identifier: Curve {
    /// Object Identifier (OID) for this curve
    const OID: oid::ObjectIdentifier;
}
