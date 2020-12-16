//! Elliptic Curve Diffie-Hellman (Ephemeral) Support.
//!
//! This module contains a generic ECDH implementation which is usable with
//! any elliptic curve which implements the [`ProjectiveArithmetic`] trait (presently
//! the `k256` and `p256` crates)
//!
//! # Usage
//!
//! Have each participant generate an [`EphemeralSecret`] value, compute the
//! [`PublicKey`] for that value, exchange public keys, then each participant
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
    public_key::PublicKey,
    scalar::NonZeroScalar,
    sec1::{EncodedPoint, ToEncodedPoint, UncompressedPointSize, UntaggedPointSize},
    weierstrass::Curve,
    AffinePoint, FieldBytes, ProjectiveArithmetic, ProjectivePoint, Scalar,
};
use core::{fmt::Debug, ops::Add};
use ff::PrimeField;
use generic_array::ArrayLength;
use group::{Curve as _, Group};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

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
    AffinePoint<C>: Copy + Clone + Debug + ToEncodedPoint<C> + Zeroize,
    ProjectivePoint<C>: From<AffinePoint<C>>,
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
        PublicKey::from_affine((C::ProjectivePoint::generator() * self.scalar.as_ref()).to_affine())
    }

    /// Compute a Diffie-Hellman shared secret from an ephemeral secret and the
    /// public key of the other participant in the exchange.
    pub fn diffie_hellman(&self, public_key: &PublicKey<C>) -> SharedSecret<C> {
        #[allow(clippy::op_ref)]
        let shared_secret = public_key.to_projective() * &*self.scalar;
        // SharedSecret::new expects an uncompressed point
        SharedSecret::new(
            shared_secret
                .to_affine()
                .to_encoded_point(false)
                .expect("secret is identity"),
        )
    }
}

impl<C> From<&EphemeralSecret<C>> for PublicKey<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>> + Clone + Zeroize,
    AffinePoint<C>: Copy + Clone + Debug + ToEncodedPoint<C> + Zeroize,
    ProjectivePoint<C>: From<AffinePoint<C>>,
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
