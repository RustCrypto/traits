//! General purpose Elliptic Curve Cryptography (ECC) support, including types
//! and traits for representing various elliptic curve forms, scalars, points,
//! and public/secret keys composed thereof.
//!
//! ## Minimum Supported Rust Version
//!
//! Rust **1.51** or higher.
//!
//! Minimum supported Rust version can be changed in the future, but it will be
//! done with a minor version bump.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code, clippy::unwrap_used)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_root_url = "https://docs.rs/elliptic-curve/0.10.6"
)]

#[cfg(feature = "alloc")]
#[allow(unused_imports)]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "rand_core")]
#[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
pub use rand_core;

pub mod ops;
pub mod sec1;
pub mod weierstrass;

mod error;
mod scalar;

#[cfg(feature = "arithmetic")]
mod arithmetic;
#[cfg(feature = "arithmetic")]
mod public_key;

#[cfg(feature = "dev")]
#[cfg_attr(docsrs, doc(cfg(feature = "dev")))]
pub mod dev;

#[cfg(feature = "ecdh")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdh")))]
pub mod ecdh;

#[cfg(feature = "jwk")]
mod jwk;

#[cfg(feature = "zeroize")]
mod secret_key;

pub use self::{
    error::{Error, Result},
    scalar::bytes::ScalarBytes,
};
pub use crypto_bigint as bigint;
pub use generic_array::{self, typenum::consts};
pub use rand_core;
pub use subtle;

#[cfg(feature = "arithmetic")]
pub use {
    crate::{
        arithmetic::{AffineArithmetic, ProjectiveArithmetic, ScalarArithmetic},
        public_key::PublicKey,
        scalar::{non_zero::NonZeroScalar, Scalar},
    },
    ff::Field,
    group::{self, Group},
};

#[cfg(feature = "bits")]
pub use crate::scalar::ScalarBits;

#[cfg(feature = "jwk")]
pub use crate::jwk::{JwkEcKey, JwkParameters};

#[cfg(feature = "pkcs8")]
pub use pkcs8;

#[cfg(feature = "zeroize")]
pub use secret_key::SecretKey;
#[cfg(feature = "zeroize")]
pub use zeroize;

use core::fmt::Debug;
use generic_array::GenericArray;
use subtle::{ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess};

/// Algorithm [`ObjectIdentifier`][`pkcs8::ObjectIdentifier`] for elliptic
/// curve public key cryptography.
///
/// <http://oid-info.com/get/1.2.840.10045.2.1>
#[cfg(feature = "pkcs8")]
#[cfg_attr(docsrs, doc(cfg(feature = "pkcs8")))]
pub const ALGORITHM_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new("1.2.840.10045.2.1");

/// Elliptic curve.
///
/// This trait is intended to be impl'd by a ZST which represents a concrete
/// elliptic curve.
///
/// Other traits in this crate which are bounded by [`Curve`] are intended to
/// be impl'd by these ZSTs, facilitating types which are generic over elliptic
/// curves (e.g. [`SecretKey`]).
pub trait Curve: Clone + Debug + Default + Eq + Ord + Send + Sync {
    /// Integer type used to represent field elements of this elliptic curve.
    // TODO(tarcieri): replace this with an e.g. `const Curve::MODULUS: uint`.
    // Requires rust-lang/rust#60551, i.e. `const_evaluatable_checked`
    type UInt: AsRef<[bigint::Limb]>
        + bigint::ArrayEncoding
        + bigint::Encoding
        + Copy
        + Debug
        + Default
        + ConstantTimeEq
        + ConstantTimeGreater
        + ConstantTimeLess;

    /// Order constant.
    ///
    /// Subdivided into either 32-bit or 64-bit "limbs" (depending on the
    /// target CPU's word size), specified from least to most significant.
    const ORDER: Self::UInt;
}

/// Size of field elements of this elliptic curve.
pub type FieldSize<C> = <<C as Curve>::UInt as bigint::ArrayEncoding>::ByteSize;

/// Byte representation of a base/scalar field element of a given curve.
pub type FieldBytes<C> = GenericArray<u8, FieldSize<C>>;

/// Affine point type for a given curve with a [`ProjectiveArithmetic`]
/// implementation.
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
#[cfg(feature = "arithmetic")]
pub type AffinePoint<C> = <C as AffineArithmetic>::AffinePoint;

/// Projective point type for a given curve with a [`ProjectiveArithmetic`]
/// implementation.
#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub type ProjectivePoint<C> = <C as ProjectiveArithmetic>::ProjectivePoint;

/// Associate an [`ObjectIdentifier`][`pkcs8::ObjectIdentifier`] (OID) with an
/// elliptic curve algorithm implementation.
///
/// This is used as as the `parameters` of an `AlgorithmIdentifier` as
/// described in RFC 5280 Section 4.1.1.2:
/// <https://tools.ietf.org/html/rfc5280#section-4.1.1.2>
#[cfg(feature = "pkcs8")]
#[cfg_attr(docsrs, doc(cfg(feature = "pkcs8")))]
pub trait AlgorithmParameters: Curve {
    /// Object Identifier (OID) for this curve
    const OID: pkcs8::ObjectIdentifier;

    /// Get the [`pkcs8::AlgorithmIdentifier`] for this curve
    fn algorithm_identifier() -> pkcs8::AlgorithmIdentifier<'static> {
        pkcs8::AlgorithmIdentifier {
            oid: ALGORITHM_OID,
            parameters: Some((&Self::OID).into()),
        }
    }
}
