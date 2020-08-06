//! Public keys for Weierstrass curves: wrapper around compressed or
//! uncompressed elliptic curve points.

use super::{
    point::{CompressedPoint, CompressedPointSize, UncompressedPoint, UncompressedPointSize},
    Curve,
};
use crate::{point::Generator, scalar::NonZeroScalar, Arithmetic, Error, FromBytes, SecretKey};
use core::{
    convert::TryFrom,
    fmt::{self, Debug},
    ops::{Add, Mul},
};
use generic_array::{
    typenum::{Unsigned, U1},
    ArrayLength, GenericArray,
};
use subtle::CtOption;

/// Size of an untagged point for given elliptic curve.
pub type UntaggedPointSize<C> = <<C as crate::Curve>::ElementSize as Add>::Output;

/// Public keys for Weierstrass curves
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord)]
pub enum PublicKey<C>
where
    C: Curve,
    C::ElementSize: Add<U1>,
    <C::ElementSize as Add>::Output: Add<U1>,
    CompressedPointSize<C>: ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// Compressed Weierstrass elliptic curve point
    Compressed(CompressedPoint<C>),

    /// Uncompressed Weierstrass elliptic curve point
    Uncompressed(UncompressedPoint<C>),
}

impl<C> PublicKey<C>
where
    C: Curve,
    C::ElementSize: Add<U1>,
    <C::ElementSize as Add>::Output: Add<U1>,
    CompressedPointSize<C>: ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// Decode public key from an elliptic curve point
    /// (compressed or uncompressed) encoded using the
    /// `Elliptic-Curve-Point-to-Octet-String` algorithm described in
    /// SEC 1: Elliptic Curve Cryptography (Version 2.0) section
    /// 2.3.3 (page 10).
    ///
    /// <http://www.secg.org/sec1-v2.pdf>
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Option<Self> {
        let slice = bytes.as_ref();
        let length = slice.len();

        if length == <CompressedPointSize<C>>::to_usize() {
            let array = GenericArray::clone_from_slice(slice);
            let point = CompressedPoint::from_bytes(array)?;
            Some(PublicKey::Compressed(point))
        } else if length == <UncompressedPointSize<C>>::to_usize() {
            let array = GenericArray::clone_from_slice(slice);
            let point = UncompressedPoint::from_bytes(array)?;
            Some(PublicKey::Uncompressed(point))
        } else {
            None
        }
    }

    /// Decode public key from a raw uncompressed point serialized
    /// as a bytestring, without a `0x04`-byte tag.
    ///
    /// This will be twice the modulus size, or 1-byte smaller than the
    /// `Elliptic-Curve-Point-to-Octet-String` encoding i.e
    /// with the leading `0x04` byte in that encoding removed.
    pub fn from_untagged_point(bytes: &GenericArray<u8, UntaggedPointSize<C>>) -> Self
    where
        <C::ElementSize as Add>::Output: ArrayLength<u8>,
    {
        let mut tagged_bytes = GenericArray::default();
        tagged_bytes.as_mut_slice()[0] = 0x04;
        tagged_bytes.as_mut_slice()[1..].copy_from_slice(bytes.as_ref());

        PublicKey::Uncompressed(UncompressedPoint::from_bytes(tagged_bytes).unwrap())
    }

    /// Compress this [`PublicKey`].
    ///
    /// If the key is already compressed, this is a no-op.
    pub fn compress(&mut self) {
        if let PublicKey::Uncompressed(point) = self {
            *self = CompressedPoint::from_affine_coords(point.x(), point.y()).into();
        }
    }

    /// Obtain public key as a byte array reference
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            PublicKey::Compressed(ref point) => point.as_bytes(),
            PublicKey::Uncompressed(ref point) => point.as_bytes(),
        }
    }
}

impl<C> PublicKey<C>
where
    C: Curve + Arithmetic,
    C::AffinePoint: Mul<NonZeroScalar<C>, Output = C::AffinePoint>,
    C::ElementSize: Add<U1>,
    <C::ElementSize as Add>::Output: Add<U1>,
    CompressedPoint<C>: From<C::AffinePoint>,
    UncompressedPoint<C>: From<C::AffinePoint>,
    CompressedPointSize<C>: ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// Compute the [`PublicKey`] for the provided [`SecretKey`].
    ///
    /// The `compress` flag requests point compression.
    pub fn from_secret_key(secret_key: &SecretKey<C>, compress: bool) -> Result<Self, Error> {
        let ct_option = C::Scalar::from_bytes(secret_key.as_bytes()).and_then(NonZeroScalar::new);

        if ct_option.is_none().into() {
            return Err(Error);
        }

        let affine_point = C::AffinePoint::generator() * ct_option.unwrap();

        if compress {
            Ok(PublicKey::Compressed(affine_point.into()))
        } else {
            Ok(PublicKey::Uncompressed(affine_point.into()))
        }
    }
}

impl<C> AsRef<[u8]> for PublicKey<C>
where
    C: Curve,
    C::ElementSize: Add<U1>,
    <C::ElementSize as Add>::Output: Add<U1>,
    CompressedPointSize<C>: ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<C> Copy for PublicKey<C>
where
    C: Curve,
    C::ElementSize: Add<U1>,
    <C::ElementSize as Add>::Output: Add<U1>,
    CompressedPointSize<C>: ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
    <CompressedPointSize<C> as ArrayLength<u8>>::ArrayType: Copy,
    <UncompressedPointSize<C> as ArrayLength<u8>>::ArrayType: Copy,
{
}

impl<C> Debug for PublicKey<C>
where
    C: Curve,
    C::ElementSize: Add<U1>,
    <C::ElementSize as Add>::Output: Add<U1>,
    CompressedPointSize<C>: ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey<{:?}>({:?})", C::default(), self.as_ref())
    }
}

impl<C> TryFrom<&SecretKey<C>> for PublicKey<C>
where
    C: Curve + Arithmetic,
    C::AffinePoint: Mul<NonZeroScalar<C>, Output = C::AffinePoint>,
    C::ElementSize: Add<U1>,
    <C::ElementSize as Add>::Output: Add<U1>,
    CompressedPoint<C>: From<C::AffinePoint>,
    UncompressedPoint<C>: From<C::AffinePoint>,
    CompressedPointSize<C>: ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    type Error = Error;

    fn try_from(secret_key: &SecretKey<C>) -> Result<Self, Error> {
        Self::from_secret_key(secret_key, C::COMPRESS_POINTS)
    }
}

impl<C> From<CompressedPoint<C>> for PublicKey<C>
where
    C: Curve,
    C::ElementSize: Add<U1>,
    <C::ElementSize as Add>::Output: Add<U1>,
    CompressedPointSize<C>: ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    fn from(point: CompressedPoint<C>) -> Self {
        PublicKey::Compressed(point)
    }
}

impl<C> From<UncompressedPoint<C>> for PublicKey<C>
where
    C: Curve,
    C::ElementSize: Add<U1>,
    <C::ElementSize as Add>::Output: Add<U1>,
    CompressedPointSize<C>: ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    fn from(point: UncompressedPoint<C>) -> Self {
        PublicKey::Uncompressed(point)
    }
}

/// Trait for deserializing a value from a public key.
///
/// This is intended for use with the `AffinePoint` type for a given elliptic curve.
pub trait FromPublicKey<C>: Sized
where
    C: Curve,
    C::ElementSize: Add<U1>,
    <C::ElementSize as Add>::Output: Add<U1>,
    CompressedPointSize<C>: ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// Deserialize this value from a [`PublicKey`]
    ///
    /// # Returns
    ///
    /// `None` if the public key is not on the curve.
    fn from_public_key(public_key: &PublicKey<C>) -> CtOption<Self>;
}
