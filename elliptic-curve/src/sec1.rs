//! SEC1 encoding support.
//!
//! Support for the `Elliptic-Curve-Point-to-Octet-String` encoding described
//! in SEC1: Elliptic Curve Cryptography (Version 2.0) section 2.3.3 (p.10):
//!
//! <https://www.secg.org/sec1-v2.pdf>

use crate::ElementBytes;
use crate::{weierstrass::Curve, Error};
use core::{
    fmt::{self, Debug},
    ops::Add,
};
use generic_array::{
    typenum::{Unsigned, U1},
    ArrayLength, GenericArray,
};
use subtle::CtOption;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Size of a compressed elliptic curve point for the given curve when
/// serialized using `Elliptic-Curve-Point-to-Octet-String` encoding
/// (including leading `0x02` or `0x03` tag byte).
pub type CompressedPointSize<C> = <<C as crate::Curve>::ElementSize as Add<U1>>::Output;

/// Size of an uncompressed elliptic curve point for the given curve when
/// serialized using the `Elliptic-Curve-Point-to-Octet-String` encoding
/// (including leading `0x04` tag byte).
pub type UncompressedPointSize<C> = <UntaggedPointSize<C> as Add<U1>>::Output;

/// Size of an untagged point for given elliptic curve.
pub type UntaggedPointSize<C> = <<C as crate::Curve>::ElementSize as Add>::Output;

/// SEC1 encoded curve point.
///
/// This type is an enum over the compressed and uncompressed encodings,
/// useful for cases where either encoding can be supported, or conversions
/// between the two forms.
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct EncodedPoint<C>
where
    C: Curve,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    bytes: GenericArray<u8, UncompressedPointSize<C>>,
}

#[allow(clippy::len_without_is_empty)]
impl<C> EncodedPoint<C>
where
    C: Curve,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// Decode elliptic curve point (compressed or uncompressed) from the
    /// `Elliptic-Curve-Point-to-Octet-String` encoding described in
    /// SEC 1: Elliptic Curve Cryptography (Version 2.0) section
    /// 2.3.3 (page 10).
    ///
    /// <http://www.secg.org/sec1-v2.pdf>
    pub fn from_bytes(input: impl AsRef<[u8]>) -> Result<Self, Error> {
        let input = input.as_ref();

        // Validate tag
        let tag = input.first().cloned().ok_or(Error).and_then(Tag::from_u8)?;

        // Validate length
        let expected_len = if tag.is_compressed() {
            C::ElementSize::to_usize() + 1
        } else {
            UncompressedPointSize::<C>::to_usize()
        };

        if input.len() == expected_len {
            let mut bytes = GenericArray::default();
            bytes[..expected_len].copy_from_slice(input);
            Ok(Self { bytes })
        } else {
            Err(Error)
        }
    }

    /// Compress and serialize an elliptic curve point from its affine coordinates
    pub fn from_affine_coords(x: &ElementBytes<C>, y: &ElementBytes<C>, compress: bool) -> Self {
        let tag = if compress {
            Tag::compress_y(y.as_slice())
        } else {
            Tag::Uncompressed
        };

        let mut bytes = GenericArray::default();
        bytes[0] = tag.into();

        let element_size = C::ElementSize::to_usize();
        bytes[1..(element_size + 1)].copy_from_slice(x);

        if !compress {
            bytes[(element_size + 1)..].copy_from_slice(y);
        }

        Self { bytes }
    }

    /// Decode elliptic curve from a raw uncompressed point, i.e. one encoded
    /// as `x || y` with no leading `Elliptic-Curve-Point-to-Octet-String` tag
    /// byte (which would otherwise be `0x04` for an uncompressed point).
    pub fn from_untagged_point(bytes: &GenericArray<u8, UntaggedPointSize<C>>) -> Self {
        let (x, y) = bytes.split_at(C::ElementSize::to_usize());
        Self::from_affine_coords(x.into(), y.into(), false)
    }

    /// Is this [`EncodedPoint`] compressed?
    pub fn is_compressed(&self) -> bool {
        self.tag().is_compressed()
    }

    /// Get the length of the encoded point in bytes
    pub fn len(&self) -> usize {
        if self.is_compressed() {
            C::ElementSize::to_usize() + 1
        } else {
            UncompressedPointSize::<C>::to_usize()
        }
    }

    /// Get byte slice of the [`EncodedPoint`].
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len()]
    }

    /// Compress this [`EncodedPoint`], returning a new [`EncodedPoint`].
    pub fn compress(&self) -> Self {
        if self.tag().is_compressed() {
            self.clone()
        } else {
            Self::from_affine_coords(self.x(), self.y().unwrap(), true)
        }
    }

    /// Decode this [`EncodedPoint`] into the desired type
    pub fn decode<T>(&self) -> CtOption<T>
    where
        T: FromEncodedPoint<C>,
    {
        T::from_encoded_point(self)
    }

    /// Get the x-coordinate for this [`EncodedPoint`]
    #[cfg(feature = "ecdh")]
    pub(crate) fn x(&self) -> &ElementBytes<C> {
        self.coordinates().0
    }

    /// Get the y-coordinate for this [`EncodedPoint`].
    ///
    /// Returns `None` if this point is compressed.
    fn y(&self) -> Option<&ElementBytes<C>> {
        self.coordinates().1
    }

    /// Get the coordinates for this [`EncodedPoint`] as a pair
    #[inline]
    fn coordinates(&self) -> (&ElementBytes<C>, Option<&ElementBytes<C>>) {
        let (x, y) = self.bytes[1..].split_at(C::ElementSize::to_usize());

        if self.is_compressed() {
            (x.into(), None)
        } else {
            (x.into(), Some(y.into()))
        }
    }

    /// Get the SEC1 tag for this [`EncodedPoint`]
    fn tag(&self) -> Tag {
        // Tag is ensured valid by the constructor
        Tag::from_u8(self.bytes[0]).expect("invalid tag")
    }
}

impl<C> AsRef<[u8]> for EncodedPoint<C>
where
    C: Curve,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
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
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
    <UncompressedPointSize<C> as ArrayLength<u8>>::ArrayType: Copy,
{
}

impl<C> Debug for EncodedPoint<C>
where
    C: Curve,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EncodedPoint<{:?}>({:?})", C::default(), &self.bytes)
    }
}

#[cfg(feature = "zeroize")]
impl<C> Zeroize for EncodedPoint<C>
where
    C: Curve,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    fn zeroize(&mut self) {
        self.bytes.zeroize()
    }
}

/// Trait for deserializing a value from a SEC1 encoded curve point.
///
/// This is intended for use with the `AffinePoint` type for a given elliptic curve.
pub trait FromEncodedPoint<C>: Sized
where
    C: Curve,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// Deserialize the type this trait is impl'd on from an [`EncodedPoint`].
    ///
    /// # Returns
    ///
    /// `None` if the [`EncodedPoint`] is invalid.
    fn from_encoded_point(public_key: &EncodedPoint<C>) -> CtOption<Self>;
}

/// Tag byte used by the `Elliptic-Curve-Point-to-Octet-String` encoding.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
enum Tag {
    /// Compressed point with even y-coordinate
    CompressedEvenY = 2,

    /// Compressed point with odd y-coordinate
    CompressedOddY = 3,

    /// Uncompressed point
    Uncompressed = 4,
}

impl Tag {
    /// Parse a tag value from a byte
    pub fn from_u8(byte: u8) -> Result<Self, Error> {
        match byte {
            2 => Ok(Tag::CompressedEvenY),
            3 => Ok(Tag::CompressedOddY),
            4 => Ok(Tag::Uncompressed),
            _ => Err(Error),
        }
    }

    /// Compress the given y-coordinate, returning a `Tag::Compressed*` value
    pub fn compress_y(y: &[u8]) -> Self {
        debug_assert!(!y.is_empty());

        // Is the y-coordinate odd in the SEC1 sense: `self mod 2 == 1`?
        if y.as_ref().last().unwrap() & 1 == 1 {
            Tag::CompressedOddY
        } else {
            Tag::CompressedEvenY
        }
    }

    /// Is this point compressed?
    pub fn is_compressed(self) -> bool {
        match self {
            Tag::CompressedEvenY | Tag::CompressedOddY => true,
            Tag::Uncompressed => false,
        }
    }
}

impl From<Tag> for u8 {
    fn from(tag: Tag) -> u8 {
        tag as u8
    }
}
