//! Elliptic Curve Diffie-Hellman (Ephemeral) Support.
//!
//! This module contains a generic ECDH implementation which is usable with
//! any elliptic curve which implements the [`ProjectiveArithmetic`] trait (presently
//! the `k256` and `p256` crates)
//!
//! # Usage
//!
//! Have each participant generate an [`EphemeralSecret`] value, compute the
//! [`PublicKey'] for that value, exchange public keys, then each participant
//! uses their [`EphemeralSecret`] and the other participant's [`PublicKey`]
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
    generic_array::ArrayLength,
    scalar::NonZeroScalar,
    sec1::{
        EncodedPoint, FromEncodedPoint, ToEncodedPoint, UncompressedPointSize, UntaggedPointSize,
    },
    weierstrass::Curve,
    AffinePoint, Error, FieldBytes, ProjectiveArithmetic, Scalar,
};
use core::{
    fmt::Debug,
    ops::{Add, Mul},
};
use ff::PrimeField;
use group::{Curve as _, Group};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// Elliptic Curve Diffie-Hellman public keys.
///
/// These are [`AffinePoint`]s. That is, they are non-identity curve points.
#[derive(Clone, Debug)]
pub struct PublicKey<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>,
    AffinePoint<C>: Clone + Debug + Default + FromEncodedPoint<C> + ToEncodedPoint<C>,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    point: AffinePoint<C>,
}

impl<C> PublicKey<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>,
    AffinePoint<C>: Clone + Debug + Default + FromEncodedPoint<C> + ToEncodedPoint<C>,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// Initialize [`PublicKey`] from a SEC1-encoded public key
    pub fn new(bytes: &[u8]) -> Result<Self, Error> {
        EncodedPoint::from_bytes(bytes)
            .map_err(|_| Error)
            .and_then(|point| Self::from_encoded_point(&point))
    }

    /// Initialize [`PublicKey`] from an [`EncodedPoint`]
    pub fn from_encoded_point(encoded_point: &EncodedPoint<C>) -> Result<Self, Error> {
        let affine_point = AffinePoint::<C>::from_encoded_point(encoded_point);

        // No need to return a CtOption when the input is assumed to be public
        if affine_point.is_some().into() {
            Ok(Self {
                point: affine_point.unwrap(),
            })
        } else {
            Err(Error)
        }
    }
}

impl<C> ToEncodedPoint<C> for PublicKey<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>,
    AffinePoint<C>: Clone + Debug + Default + FromEncodedPoint<C> + ToEncodedPoint<C>,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// Serialize this [`PublicKey`] as a SEC1 [`EncodedPoint`], optionally applying
    /// point compression
    fn to_encoded_point(&self, compress: bool) -> EncodedPoint<C> {
        self.point.to_encoded_point(compress)
    }
}

/// Ephemeral Diffie-Hellman Secret.
///
/// These are ephemeral "secret key" values which are deliberately designed
/// to avoid being persisted.
pub struct EphemeralSecret<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>> + Zeroize,
{
    scalar: NonZeroScalar<C>,
}

impl<C> EphemeralSecret<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>> + Clone + Zeroize,
    AffinePoint<C>: Clone
        + Debug
        + Default
        + Into<EncodedPoint<C>>
        + FromEncodedPoint<C>
        + ToEncodedPoint<C>
        + Mul<NonZeroScalar<C>, Output = AffinePoint<C>>
        + Zeroize,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// Generate a cryptographically random [`EphemeralSecret`].
    pub fn random(rng: impl CryptoRng + RngCore) -> Self {
        Self {
            scalar: NonZeroScalar::random(rng),
        }
    }

    /// Get the public key associated with this ephemeral secret.
    ///
    /// The `compress` flag enables point compression.
    pub fn public_key(&self) -> PublicKey<C> {
        #[allow(clippy::op_ref)]
        let pubkey_point = (C::ProjectivePoint::generator() * &*self.scalar).to_affine();

        PublicKey {
            point: pubkey_point,
        }
    }

    /// Compute a Diffie-Hellman shared secret from an ephemeral secret and the
    /// public key of the other participant in the exchange.
    pub fn diffie_hellman(&self, public_key: &PublicKey<C>) -> SharedSecret<C> {
        let shared_secret = public_key.point.clone() * self.scalar;
        // SharedSecret::new expects an uncompressed point
        SharedSecret::new(shared_secret.to_encoded_point(false))
    }
}

impl<C> From<&EphemeralSecret<C>> for PublicKey<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>> + Clone + Zeroize,
    AffinePoint<C>: Clone
        + Debug
        + Default
        + Into<EncodedPoint<C>>
        + FromEncodedPoint<C>
        + ToEncodedPoint<C>
        + Mul<NonZeroScalar<C>, Output = AffinePoint<C>>
        + Zeroize,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    fn from(ephemeral_secret: &EphemeralSecret<C>) -> Self {
        ephemeral_secret.public_key()
    }
}

impl<C> Zeroize for EphemeralSecret<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>> + Zeroize,
{
    fn zeroize(&mut self) {
        self.scalar.zeroize()
    }
}

impl<C> Drop for EphemeralSecret<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>> + Zeroize,
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
pub struct SharedSecret<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>,
{
    /// Computed secret value
    secret_bytes: FieldBytes<C>,
}

impl<C> SharedSecret<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>,
    AffinePoint<C>: Zeroize,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// Create a new shared secret from the given uncompressed curve point
    fn new(mut encoded_point: EncodedPoint<C>) -> Self {
        let secret_bytes = encoded_point.x().clone();
        encoded_point.zeroize();
        Self { secret_bytes }
    }

    /// Shared secret value, serialized as bytes.
    ///
    /// As noted in the comments for this struct, this value is non-uniform and
    /// should not be used directly as a symmetric encryption key, but instead
    /// as input to a KDF (or failing that, a hash function) used to produce
    /// a symmetric key.
    pub fn as_bytes(&self) -> &FieldBytes<C> {
        &self.secret_bytes
    }
}

impl<C> Zeroize for SharedSecret<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>,
{
    fn zeroize(&mut self) {
        self.secret_bytes.zeroize()
    }
}

impl<C> Drop for SharedSecret<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}
