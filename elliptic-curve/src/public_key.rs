//! Elliptic curve public keys.

use crate::{
    consts::U1,
    sec1::{
        EncodedPoint, FromEncodedPoint, ToEncodedPoint, UncompressedPointSize, UntaggedPointSize,
    },
    weierstrass::{point, Curve},
    AffinePoint, Error, FieldBytes, ProjectiveArithmetic, ProjectivePoint, Scalar,
};
use core::{
    convert::{TryFrom, TryInto},
    fmt::Debug,
    ops::Add,
};
use ff::PrimeField;
use generic_array::ArrayLength;

/// Elliptic curve public keys.
///
/// These are a thin wrapper around [`AffinePoint`] which simplifies
/// encoding/decoding.
#[derive(Clone, Debug)]
pub struct PublicKey<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>,
    AffinePoint<C>: Clone + Debug + Default + FromEncodedPoint<C> + ToEncodedPoint<C>,
    ProjectivePoint<C>: From<AffinePoint<C>>,
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
    ProjectivePoint<C>: From<AffinePoint<C>>,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// Convert an [`AffinePoint`] into a [`PublicKey`]
    pub fn from_affine(point: AffinePoint<C>) -> Self {
        Self { point }
    }

    /// Decode [`PublicKey`] (compressed or uncompressed) from the
    /// `Elliptic-Curve-Point-to-Octet-String` encoding described in
    /// SEC 1: Elliptic Curve Cryptography (Version 2.0) section
    /// 2.3.3 (page 10).
    ///
    /// <http://www.secg.org/sec1-v2.pdf>
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, Error> {
        EncodedPoint::from_bytes(bytes)
            .map_err(|_| Error)
            .and_then(TryInto::try_into)
    }

    /// Borrow the inner [`AffinePoint`] from this [`PublicKey`].
    ///
    /// In ECC, public keys are elliptic curve points.
    pub fn as_affine(&self) -> &AffinePoint<C> {
        &self.point
    }

    /// Convert this [`PublicKey`] to a [`ProjectivePoint`] for the given curve
    pub fn to_projective(&self) -> ProjectivePoint<C> {
        self.point.clone().into()
    }
}

impl<C> AsRef<AffinePoint<C>> for PublicKey<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>,
    AffinePoint<C>: Clone + Debug + Default + FromEncodedPoint<C> + ToEncodedPoint<C>,
    ProjectivePoint<C>: From<AffinePoint<C>>,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    fn as_ref(&self) -> &AffinePoint<C> {
        self.as_affine()
    }
}

impl<C> TryFrom<EncodedPoint<C>> for PublicKey<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>,
    AffinePoint<C>: Clone + Debug + Default + FromEncodedPoint<C> + ToEncodedPoint<C>,
    ProjectivePoint<C>: From<AffinePoint<C>>,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    type Error = Error;

    fn try_from(encoded_point: EncodedPoint<C>) -> Result<Self, Error> {
        encoded_point.decode()
    }
}

impl<C> TryFrom<&EncodedPoint<C>> for PublicKey<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>,
    AffinePoint<C>: Clone + Debug + Default + FromEncodedPoint<C> + ToEncodedPoint<C>,
    ProjectivePoint<C>: From<AffinePoint<C>>,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    type Error = Error;

    fn try_from(encoded_point: &EncodedPoint<C>) -> Result<Self, Error> {
        encoded_point.decode()
    }
}

impl<C> From<PublicKey<C>> for EncodedPoint<C>
where
    C: Curve + ProjectiveArithmetic + point::Compression,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>,
    AffinePoint<C>: Clone + Debug + Default + FromEncodedPoint<C> + ToEncodedPoint<C>,
    ProjectivePoint<C>: From<AffinePoint<C>>,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    fn from(public_key: PublicKey<C>) -> EncodedPoint<C> {
        EncodedPoint::<C>::from(&public_key)
    }
}

impl<C> From<&PublicKey<C>> for EncodedPoint<C>
where
    C: Curve + ProjectiveArithmetic + point::Compression,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>,
    AffinePoint<C>: Clone + Debug + Default + FromEncodedPoint<C> + ToEncodedPoint<C>,
    ProjectivePoint<C>: From<AffinePoint<C>>,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    fn from(public_key: &PublicKey<C>) -> EncodedPoint<C> {
        public_key.to_encoded_point(C::COMPRESS_POINTS)
    }
}

impl<C> FromEncodedPoint<C> for PublicKey<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>,
    AffinePoint<C>: Clone + Debug + Default + FromEncodedPoint<C> + ToEncodedPoint<C>,
    ProjectivePoint<C>: From<AffinePoint<C>>,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// Initialize [`PublicKey`] from an [`EncodedPoint`]
    fn from_encoded_point(encoded_point: &EncodedPoint<C>) -> Option<Self> {
        AffinePoint::<C>::from_encoded_point(encoded_point).map(|point| Self { point })
    }
}

impl<C> ToEncodedPoint<C> for PublicKey<C>
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>>,
    AffinePoint<C>: Clone + Debug + Default + FromEncodedPoint<C> + ToEncodedPoint<C>,
    ProjectivePoint<C>: From<AffinePoint<C>>,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// Serialize this [`PublicKey`] as a SEC1 [`EncodedPoint`], optionally applying
    /// point compression
    fn to_encoded_point(&self, compress: bool) -> EncodedPoint<C> {
        self.point.to_encoded_point(compress)
    }
}
