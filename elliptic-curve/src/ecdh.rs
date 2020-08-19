//! Elliptic Curve Diffie-Hellman (Ephemeral) Support.
//!
//! This module contains a generic ECDH implementation which is usable with
//! any elliptic curve which implements the [`Arithmetic`] trait (presently
//! the `k256` and `p256` crates)
//!
//! # Usage
//!
//! Have each participant generate an [`EphemeralSecret`] value, compute the
//! [`EncodedPoint`] for that value, exchange public keys, then each participant
//! uses their [`EphemeralSecret`] and the other participant's [`EncodedPoint`]
//! to compute a [`SharedSecret`] value.
//!
//! # ⚠️ SECURITY WARNING ⚠️
//!
//! Ephemeral Diffie-Hellman exchanges are unauthenticated and without a
//! further authentication step are trivially vulnerable to man-in-the-middle
//! attacks!
//!
//! These exchanges should be performed in the context of a protocol which
//! takes further steps to authenticate the peers in a key exchange.

use crate::{
    consts::U1,
    point::Generator,
    scalar::NonZeroScalar,
    sec1::{
        self, CompressedPoint, CompressedPointSize, FromEncodedPoint, UncompressedPoint,
        UncompressedPointSize,
    },
    weierstrass::Curve,
    Arithmetic, ElementBytes, Error, Generate,
};
use core::ops::{Add, Mul};
use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// Elliptic Curve Diffie-Hellman public keys.
///
/// These are SEC1-encoded elliptic curve points.
pub type PublicKey<C> = sec1::EncodedPoint<C>;

/// Ephemeral Diffie-Hellman Secret.
///
/// These are ephemeral "secret key" values which are deliberately designed
/// to avoid being persisted.
pub struct EphemeralSecret<C>
where
    C: Curve + Arithmetic,
    C::Scalar: Generate + Zeroize,
{
    scalar: NonZeroScalar<C>,
}

impl<C> EphemeralSecret<C>
where
    C: Curve + Arithmetic,
    C::Scalar: Clone + Generate + Zeroize,
    C::AffinePoint: FromEncodedPoint<C> + Mul<NonZeroScalar<C>, Output = C::AffinePoint> + Zeroize,
    C::ElementSize: Add<U1>,
    <C::ElementSize as Add>::Output: Add<U1>,
    CompressedPoint<C>: From<C::AffinePoint>,
    UncompressedPoint<C>: From<C::AffinePoint>,
    CompressedPointSize<C>: ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// Generate a new [`EphemeralSecret`].
    pub fn generate(rng: impl CryptoRng + RngCore) -> Self {
        Self {
            scalar: NonZeroScalar::generate(rng),
        }
    }

    /// Get the public key associated with this ephemeral secret.
    ///
    /// The `compress` flag enables point compression.
    pub fn public_key(&self, compress: bool) -> PublicKey<C> {
        let affine_point = C::AffinePoint::generator() * self.scalar.clone();

        if compress {
            PublicKey::Compressed(affine_point.into())
        } else {
            PublicKey::Uncompressed(affine_point.into())
        }
    }

    /// Compute a Diffie-Hellman shared secret from an ephemeral secret and the
    /// public key of the other participant in the exchange.
    pub fn diffie_hellman(&self, public_key: &PublicKey<C>) -> Result<SharedSecret<C>, Error> {
        let affine_point = C::AffinePoint::from_encoded_point(public_key);

        if affine_point.is_some().into() {
            let shared_secret = affine_point.unwrap() * self.scalar.clone();
            Ok(SharedSecret::new(shared_secret.into()))
        } else {
            Err(Error)
        }
    }
}

impl<C> From<&EphemeralSecret<C>> for PublicKey<C>
where
    C: Curve + Arithmetic,
    C::Scalar: Clone + Generate + Zeroize,
    C::AffinePoint: FromEncodedPoint<C> + Mul<NonZeroScalar<C>, Output = C::AffinePoint> + Zeroize,
    C::ElementSize: Add<U1>,
    <C::ElementSize as Add>::Output: Add<U1>,
    CompressedPoint<C>: From<C::AffinePoint>,
    UncompressedPoint<C>: From<C::AffinePoint>,
    CompressedPointSize<C>: ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    fn from(ephemeral_secret: &EphemeralSecret<C>) -> Self {
        ephemeral_secret.public_key(C::COMPRESS_POINTS)
    }
}

impl<C> Zeroize for EphemeralSecret<C>
where
    C: Curve + Arithmetic,
    C::Scalar: Generate + Zeroize,
{
    fn zeroize(&mut self) {
        self.scalar.zeroize()
    }
}

impl<C> Drop for EphemeralSecret<C>
where
    C: Curve + Arithmetic,
    C::Scalar: Generate + Zeroize,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Shared secret value computed via ECDH key agreement.
///
/// This value contains the raw serialized x-coordinate of the elliptic curve
/// point computed from a Diffie-Hellman exchange.
///
/// # ⚠️ WARNING: NOT UNIFORMLY RANDOM! ⚠️
///
/// This value is not uniformly random and should not be used directly
/// as a cryptographic key for anything which requires that property
/// (e.g. symmetric ciphers).
///
/// Instead, the resulting value should be used as input to a Key Derivation
/// Function (KDF) or cryptographic hash function to produce a symmetric key.
pub struct SharedSecret<C: Curve + Arithmetic> {
    /// Computed secret value
    secret_bytes: ElementBytes<C>,
}

impl<C> SharedSecret<C>
where
    C: Curve + Arithmetic,
    C::AffinePoint: Zeroize,
    C::ElementSize: Add<U1>,
    <C::ElementSize as Add>::Output: Add<U1>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// Create a new shared secret from the given uncompressed curve point
    fn new(mut serialized_point: UncompressedPoint<C>) -> Self {
        let secret_bytes = GenericArray::clone_from_slice(
            &serialized_point.as_ref()[1..(1 + C::ElementSize::to_usize())],
        );

        serialized_point.zeroize();
        Self { secret_bytes }
    }

    /// Shared secret value, serialized as bytes.
    ///
    /// As noted in the comments for this struct, this value is non-uniform and
    /// should not be used directly as a symmetric encryption key, but instead
    /// as input to a KDF (or failing that, a hash function) used to produce
    /// a symmetric key.
    pub fn as_bytes(&self) -> &ElementBytes<C> {
        &self.secret_bytes
    }
}

impl<C> Zeroize for SharedSecret<C>
where
    C: Curve + Arithmetic,
{
    fn zeroize(&mut self) {
        self.secret_bytes.zeroize()
    }
}

impl<C> Drop for SharedSecret<C>
where
    C: Curve + Arithmetic,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}
