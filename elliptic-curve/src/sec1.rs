//! SEC1 encoding support.
//!
//! Support for the `Elliptic-Curve-Point-to-Octet-String` encoding format as
//! described in SEC1: Elliptic Curve Cryptography (Version 2.0) section 2.3.3
//! (see page 10):
//!
//! <https://www.secg.org/sec1-v2.pdf>

use crate::ElementBytes;
use crate::{
    point::Generator, scalar::NonZeroScalar, weierstrass::Curve, Arithmetic, Error, FromBytes,
    SecretKey,
};
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

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Size of an untagged point for given elliptic curve.
pub type UntaggedPointSize<C> = <<C as crate::Curve>::ElementSize as Add>::Output;

/// SEC1 encoded curve point.
///
/// This type is an enum over the compressed and uncompressed encodings,
/// useful for cases where either encoding can be supported, or conversions
/// between the two forms.
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord)]
pub enum EncodedPoint<C>
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

impl<C> EncodedPoint<C>
where
    C: Curve,
    C::ElementSize: Add<U1>,
    <C::ElementSize as Add>::Output: Add<U1>,
    CompressedPointSize<C>: ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// Decode elliptic curve point (compressed or uncompressed) from the
    /// `Elliptic-Curve-Point-to-Octet-String` encoding described in
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
            Some(EncodedPoint::Compressed(point))
        } else if length == <UncompressedPointSize<C>>::to_usize() {
            let array = GenericArray::clone_from_slice(slice);
            let point = UncompressedPoint::from_bytes(array)?;
            Some(EncodedPoint::Uncompressed(point))
        } else {
            None
        }
    }

    /// Decode elliptic curve from a raw uncompressed point.
    ///
    /// This will be twice the modulus size, or 1-byte smaller than the
    /// `Elliptic-Curve-Point-to-Octet-String` encoding
    /// (i.e with the leading `0x04` byte in that encoding removed).
    pub fn from_untagged_point(bytes: &GenericArray<u8, UntaggedPointSize<C>>) -> Self
    where
        <C::ElementSize as Add>::Output: ArrayLength<u8>,
    {
        let mut tagged_bytes = GenericArray::default();
        tagged_bytes.as_mut_slice()[0] = 0x04;
        tagged_bytes.as_mut_slice()[1..].copy_from_slice(bytes.as_ref());

        EncodedPoint::Uncompressed(UncompressedPoint::from_bytes(tagged_bytes).unwrap())
    }

    /// Compress this [`EncodedPoint`].
    ///
    /// If the key is already compressed, this is a no-op.
    pub fn compress(&mut self) {
        if let EncodedPoint::Uncompressed(point) = self {
            *self = CompressedPoint::from_affine_coords(point.x(), point.y()).into();
        }
    }

    /// Get byte slice of the [`EncodedPoint`].
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            EncodedPoint::Compressed(point) => point.as_bytes(),
            EncodedPoint::Uncompressed(point) => point.as_bytes(),
        }
    }
}

impl<C> EncodedPoint<C>
where
    C: Curve,
    C::ElementSize: Add<U1>,
    <C::ElementSize as Add>::Output: Add<U1>,
    CompressedPointSize<C>: ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// Decode this [`EncodedPoint`] into the desired type
    pub fn decode<T>(&self) -> CtOption<T>
    where
        T: FromEncodedPoint<C>,
    {
        T::from_encoded_point(self)
    }
}

impl<C> EncodedPoint<C>
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
    /// Compute the [`EncodedPoint`] representing the public key for the
    /// provided [`SecretKey`].
    ///
    /// The `compress` flag requests point compression.
    pub fn from_secret_key(secret_key: &SecretKey<C>, compress: bool) -> Result<Self, Error> {
        let ct_option = C::Scalar::from_bytes(secret_key.as_bytes()).and_then(NonZeroScalar::new);

        if ct_option.is_none().into() {
            return Err(Error);
        }

        let affine_point = C::AffinePoint::generator() * ct_option.unwrap();

        if compress {
            Ok(EncodedPoint::Compressed(affine_point.into()))
        } else {
            Ok(EncodedPoint::Uncompressed(affine_point.into()))
        }
    }
}

impl<C> AsRef<[u8]> for EncodedPoint<C>
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

impl<C> Copy for EncodedPoint<C>
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

impl<C> Debug for EncodedPoint<C>
where
    C: Curve,
    C::ElementSize: Add<U1>,
    <C::ElementSize as Add>::Output: Add<U1>,
    CompressedPointSize<C>: ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EncodedPoint<{:?}>(", C::default())?;

        match self {
            EncodedPoint::Compressed(point) => write!(f, "{:?}", point)?,
            EncodedPoint::Uncompressed(point) => write!(f, "{:?}", point)?,
        }

        write!(f, ")")
    }
}

impl<C> TryFrom<&SecretKey<C>> for EncodedPoint<C>
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

impl<C> From<CompressedPoint<C>> for EncodedPoint<C>
where
    C: Curve,
    C::ElementSize: Add<U1>,
    <C::ElementSize as Add>::Output: Add<U1>,
    CompressedPointSize<C>: ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    fn from(point: CompressedPoint<C>) -> Self {
        EncodedPoint::Compressed(point)
    }
}

impl<C> From<UncompressedPoint<C>> for EncodedPoint<C>
where
    C: Curve,
    C::ElementSize: Add<U1>,
    <C::ElementSize as Add>::Output: Add<U1>,
    CompressedPointSize<C>: ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    fn from(point: UncompressedPoint<C>) -> Self {
        EncodedPoint::Uncompressed(point)
    }
}

/// Trait for deserializing a value from a SEC1 encoded curve point.
///
/// This is intended for use with the `AffinePoint` type for a given elliptic curve.
pub trait FromEncodedPoint<C>: Sized
where
    C: Curve,
    C::ElementSize: Add<U1>,
    <C::ElementSize as Add>::Output: Add<U1>,
    CompressedPointSize<C>: ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// Deserialize the type this trait is impl'd on from an [`EncodedPoint`].
    ///
    /// # Returns
    ///
    /// `None` if the [`EncodedPoint`] is invalid.
    fn from_encoded_point(public_key: &EncodedPoint<C>) -> CtOption<Self>;
}

/// Size of a compressed elliptic curve point for the given curve when
/// serialized using `Elliptic-Curve-Point-to-Octet-String` encoding
/// (including leading `0x02` or `0x03` tag byte).
pub type CompressedPointSize<C> = <<C as crate::Curve>::ElementSize as Add<U1>>::Output;

/// Size of an uncompressed elliptic curve point for the given curve when
/// serialized using the `Elliptic-Curve-Point-to-Octet-String` encoding
/// (including leading `0x04` tag byte).
pub type UncompressedPointSize<C> =
    <<<C as crate::Curve>::ElementSize as Add>::Output as Add<U1>>::Output;

/// Compressed elliptic curve points serialized according to the
/// `Elliptic-Curve-Point-to-Octet-String` algorithm.
///
/// See section 2.3.3 of SEC 1: Elliptic Curve Cryptography (Version 2.0):
///
/// <https://www.secg.org/sec1-v2.pdf>
#[derive(Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct CompressedPoint<C>
where
    C: Curve,
    C::ElementSize: Add<U1>,
    CompressedPointSize<C>: ArrayLength<u8>,
{
    /// Raw serialized bytes of the compressed point
    bytes: GenericArray<u8, CompressedPointSize<C>>,
}

impl<C> CompressedPoint<C>
where
    C: Curve,
    C::ElementSize: Add<U1>,
    CompressedPointSize<C>: ArrayLength<u8>,
{
    /// Compress and serialize an elliptic curve point from its affine coordinates
    pub fn from_affine_coords(x: &ElementBytes<C>, y: &ElementBytes<C>) -> Self {
        // Is the y-coordinate odd in the SEC1 sense: `self mod 2 == 1`?
        let is_y_odd = y.as_ref().last().expect("empty field element") & 1 == 1;
        let mut bytes = GenericArray::default();
        bytes[0] = if is_y_odd { 0x03 } else { 0x02 };
        bytes[1..].copy_from_slice(x);
        Self { bytes }
    }

    /// Create a new compressed elliptic curve point
    pub fn from_bytes<B>(into_bytes: B) -> Option<Self>
    where
        B: Into<GenericArray<u8, CompressedPointSize<C>>>,
    {
        let bytes = into_bytes.into();

        match bytes[0] {
            0x02 | 0x03 => Some(Self { bytes }),
            _ => None,
        }
    }

    /// Borrow byte slice containing compressed curve point
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Obtain owned array containing compressed curve point
    #[inline]
    pub fn into_bytes(self) -> GenericArray<u8, CompressedPointSize<C>> {
        self.bytes
    }
}

impl<C> AsRef<[u8]> for CompressedPoint<C>
where
    C: Curve,
    C::ElementSize: Add<U1>,
    CompressedPointSize<C>: ArrayLength<u8>,
{
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl<C: Curve> Copy for CompressedPoint<C>
where
    C::ElementSize: Add<U1>,
    CompressedPointSize<C>: ArrayLength<u8>,
    <CompressedPointSize<C> as ArrayLength<u8>>::ArrayType: Copy,
{
}

impl<C> Clone for CompressedPoint<C>
where
    C: Curve,
    C::ElementSize: Add<U1>,
    CompressedPointSize<C>: ArrayLength<u8>,
{
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
        }
    }
}

#[cfg(feature = "zeroize")]
impl<C> Zeroize for CompressedPoint<C>
where
    C: Curve,
    C::ElementSize: Add<U1>,
    CompressedPointSize<C>: ArrayLength<u8>,
{
    fn zeroize(&mut self) {
        self.bytes.zeroize()
    }
}

/// Uncompressed elliptic curve points serialized according to the
/// `Elliptic-Curve-Point-to-Octet-String` algorithm.
///
/// See section 2.3.3 of SEC 1: Elliptic Curve Cryptography (Version 2.0):
///
/// <https://www.secg.org/sec1-v2.pdf>
#[derive(Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct UncompressedPoint<C: Curve>
where
    C::ElementSize: Add<U1>,
    <C::ElementSize as Add>::Output: Add<U1>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// Raw serialized bytes of the uncompressed point
    bytes: GenericArray<u8, UncompressedPointSize<C>>,
}

impl<C> UncompressedPoint<C>
where
    C: Curve,
    C::ElementSize: Add<U1>,
    <C::ElementSize as Add>::Output: Add<U1>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// Serialize an elliptic curve point from its affine coordinates
    pub fn from_affine_coords(x: &ElementBytes<C>, y: &ElementBytes<C>) -> Self {
        let scalar_size = C::ElementSize::to_usize();
        let mut bytes = GenericArray::default();
        bytes[0] = 0x04;
        bytes[1..(scalar_size + 1)].copy_from_slice(x);
        bytes[(scalar_size + 1)..].copy_from_slice(y);
        Self { bytes }
    }

    /// Create a new uncompressed elliptic curve point
    pub fn from_bytes<B>(into_bytes: B) -> Option<Self>
    where
        B: Into<GenericArray<u8, UncompressedPointSize<C>>>,
    {
        let bytes = into_bytes.into();

        if bytes.get(0) == Some(&0x04) {
            Some(Self { bytes })
        } else {
            None
        }
    }

    /// Borrow byte slice containing uncompressed curve point
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert [`UncompressedPoint`] into owned byte array
    #[inline]
    pub fn into_bytes(self) -> GenericArray<u8, UncompressedPointSize<C>> {
        self.bytes
    }

    /// Get the x-coordinate of this curve point
    pub(crate) fn x(&self) -> &ElementBytes<C> {
        GenericArray::from_slice(&self.bytes[1..(C::ElementSize::to_usize() + 1)])
    }

    /// Get the y-coordinate of this curve point
    pub(crate) fn y(&self) -> &ElementBytes<C> {
        GenericArray::from_slice(&self.bytes[(C::ElementSize::to_usize() + 1)..])
    }
}

impl<C> AsRef<[u8]> for UncompressedPoint<C>
where
    C: Curve,
    C::ElementSize: Add<U1>,
    <C::ElementSize as Add>::Output: Add<U1>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl<C> Copy for UncompressedPoint<C>
where
    C: Curve,
    C::ElementSize: Add<U1>,
    <C::ElementSize as Add>::Output: Add<U1>,
    UncompressedPointSize<C>: ArrayLength<u8>,
    <UncompressedPointSize<C> as ArrayLength<u8>>::ArrayType: Copy,
{
}

impl<C> Clone for UncompressedPoint<C>
where
    C: Curve,
    C::ElementSize: Add<U1>,
    <C::ElementSize as Add>::Output: Add<U1>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
        }
    }
}

#[cfg(feature = "zeroize")]
impl<C> Zeroize for UncompressedPoint<C>
where
    C: Curve,
    C::ElementSize: Add<U1>,
    <C::ElementSize as Add>::Output: Add<U1>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    fn zeroize(&mut self) {
        self.bytes.zeroize()
    }
}
