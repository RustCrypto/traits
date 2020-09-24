//! SEC1 encoding support.
//!
//! Support for the `Elliptic-Curve-Point-to-Octet-String` encoding described
//! in SEC1: Elliptic Curve Cryptography (Version 2.0) section 2.3.3 (p.10):
//!
//! <https://www.secg.org/sec1-v2.pdf>

use crate::{weierstrass::Curve, Error, FieldBytes};
use core::{
    fmt::{self, Debug},
    ops::Add,
};
use generic_array::{
    typenum::{Unsigned, U1},
    ArrayLength, GenericArray,
};
use subtle::CtOption;

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

#[cfg(feature = "arithmetic")]
use crate::{
    ff::PrimeField,
    subtle::{Choice, ConditionallySelectable},
    weierstrass::point::Decompress,
    AffinePoint, ProjectiveArithmetic, Scalar,
};

#[cfg(all(feature = "arithmetic", feature = "zeroize"))]
use crate::group::{Curve as _, Group};

#[cfg(all(feature = "arithmetic", feature = "zeroize"))]
use crate::secret_key::SecretKey;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Size of a compressed point for the given elliptic curve when encoded
/// using the SEC1 `Elliptic-Curve-Point-to-Octet-String` algorithm
/// (including leading `0x02` or `0x03` tag byte).
pub type CompressedPointSize<C> = <<C as crate::Curve>::FieldSize as Add<U1>>::Output;

/// Size of an uncompressed point for the given elliptic curve when encoded
/// using the SEC1 `Elliptic-Curve-Point-to-Octet-String` algorithm
/// (including leading `0x04` tag byte).
pub type UncompressedPointSize<C> = <UntaggedPointSize<C> as Add<U1>>::Output;

/// Size of an untagged point for given elliptic curve.
pub type UntaggedPointSize<C> = <<C as crate::Curve>::FieldSize as Add>::Output;

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
        let expected_len = tag.message_len(C::FieldSize::to_usize());

        if input.len() != expected_len {
            return Err(Error);
        }

        let mut bytes = GenericArray::default();
        bytes[..expected_len].copy_from_slice(input);
        Ok(Self { bytes })
    }

    /// Decode elliptic curve point from raw uncompressed coordinates, i.e.
    /// encoded as the concatenated `x || y` coordinates with no leading SEC1
    /// tag byte (which would otherwise be `0x04` for an uncompressed point).
    pub fn from_untagged_bytes(bytes: &GenericArray<u8, UntaggedPointSize<C>>) -> Self {
        let (x, y) = bytes.split_at(C::FieldSize::to_usize());
        Self::from_affine_coordinates(x.into(), y.into(), false)
    }

    /// Encode an elliptic curve point from big endian serialized coordinates
    /// (with optional point compression)
    pub fn from_affine_coordinates(x: &FieldBytes<C>, y: &FieldBytes<C>, compress: bool) -> Self {
        let tag = if compress {
            Tag::compress_y(y.as_slice())
        } else {
            Tag::Uncompressed
        };

        let mut bytes = GenericArray::default();
        bytes[0] = tag.into();

        let element_size = C::FieldSize::to_usize();
        bytes[1..(element_size + 1)].copy_from_slice(x);

        if !compress {
            bytes[(element_size + 1)..].copy_from_slice(y);
        }

        Self { bytes }
    }

    /// Compute [`EncodedPoint`] representing the public key for the provided
    /// [`SecretKey`].
    ///
    /// The `compress` flag requests point compression.
    #[cfg(all(feature = "arithmetic", feature = "zeroize"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
    #[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
    pub fn from_secret_key(secret_key: &SecretKey<C>, compress: bool) -> Self
    where
        C: Curve + ProjectiveArithmetic,
        FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
        AffinePoint<C>: ToEncodedPoint<C>,
        Scalar<C>: PrimeField<Repr = FieldBytes<C>> + Zeroize,
    {
        (C::ProjectivePoint::generator() * secret_key.secret_scalar())
            .to_affine()
            .to_encoded_point(compress)
    }

    /// Get the length of the encoded point in bytes
    pub fn len(&self) -> usize {
        self.tag().message_len(C::FieldSize::to_usize())
    }

    /// Get byte slice containing the serialized [`EncodedPoint`].
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len()]
    }

    /// Get boxed byte slice containing the serialized [`EncodedPoint`]
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.as_bytes().to_vec().into_boxed_slice()
    }

    /// Serialize point as raw uncompressed coordinates without tag byte, i.e.
    /// encoded as the concatenated `x || y` coordinates.
    #[cfg(feature = "arithmetic")]
    #[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
    pub fn to_untagged_bytes(&self) -> Option<GenericArray<u8, UntaggedPointSize<C>>>
    where
        C: Curve + ProjectiveArithmetic,
        FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
        Scalar<C>: PrimeField<Repr = FieldBytes<C>>,
        AffinePoint<C>: ConditionallySelectable + Default + Decompress<C> + ToEncodedPoint<C>,
    {
        let decompressed: Option<EncodedPoint<C>> = self.decompress().into();
        decompressed.map(|point| {
            let mut bytes = GenericArray::<u8, UntaggedPointSize<C>>::default();
            bytes.copy_from_slice(&point.as_bytes()[1..]);
            bytes
        })
    }

    /// Is this [`EncodedPoint`] compressed?
    pub fn is_compressed(&self) -> bool {
        self.tag().is_compressed()
    }

    /// Compress this [`EncodedPoint`], returning a new [`EncodedPoint`].
    pub fn compress(&self) -> Self {
        match self.coordinates() {
            Coordinates::Compressed { .. } => self.clone(),
            Coordinates::Uncompressed { x, y } => Self::from_affine_coordinates(x, y, true),
        }
    }

    /// Decompress this [`EncodedPoint`], returning a new [`EncodedPoint`].
    #[cfg(feature = "arithmetic")]
    #[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
    pub fn decompress(&self) -> CtOption<Self>
    where
        C: Curve + ProjectiveArithmetic,
        FieldBytes<C>: From<Scalar<C>> + for<'r> From<&'r Scalar<C>>,
        Scalar<C>: PrimeField<Repr = FieldBytes<C>>,
        AffinePoint<C>: ConditionallySelectable + Default + Decompress<C> + ToEncodedPoint<C>,
    {
        match self.coordinates() {
            Coordinates::Compressed { x, y_is_odd } => {
                AffinePoint::<C>::decompress(x, Choice::from(y_is_odd as u8))
                    .map(|s| s.to_encoded_point(false))
            }
            Coordinates::Uncompressed { .. } => CtOption::new(self.clone(), Choice::from(1)),
        }
    }

    /// Encode an [`EncodedPoint`] from the desired type
    pub fn encode<T>(encodable: T, compress: bool) -> Self
    where
        T: ToEncodedPoint<C>,
    {
        encodable.to_encoded_point(compress)
    }

    /// Decode this [`EncodedPoint`] into the desired type
    pub fn decode<T>(&self) -> CtOption<T>
    where
        T: FromEncodedPoint<C>,
    {
        T::from_encoded_point(self)
    }

    /// Get the SEC1 tag for this [`EncodedPoint`]
    pub fn tag(&self) -> Tag {
        // Tag is ensured valid by the constructor
        Tag::from_u8(self.bytes[0]).expect("invalid tag")
    }

    /// Get the [`Coordinates`] for this [`EncodedPoint`].
    #[inline]
    pub fn coordinates(&self) -> Coordinates<'_, C> {
        let (x, y) = self.bytes[1..].split_at(C::FieldSize::to_usize());

        if self.is_compressed() {
            Coordinates::Compressed {
                x: x.into(),
                y_is_odd: self.tag() as u8 & 1 == 1,
            }
        } else {
            Coordinates::Uncompressed {
                x: x.into(),
                y: y.into(),
            }
        }
    }

    /// Get the x-coordinate for this [`EncodedPoint`]
    pub fn x(&self) -> &FieldBytes<C> {
        match self.coordinates() {
            Coordinates::Compressed { x, .. } => x,
            Coordinates::Uncompressed { x, .. } => x,
        }
    }

    /// Get the y-coordinate for this [`EncodedPoint`].
    ///
    /// Returns `None` if this point is compressed.
    pub fn y(&self) -> Option<&FieldBytes<C>> {
        match self.coordinates() {
            Coordinates::Compressed { .. } => None,
            Coordinates::Uncompressed { y, .. } => Some(y),
        }
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

/// Enum representing the coordinates of either compressed or uncompressed
/// SEC1-encoded elliptic curve points.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Coordinates<'a, C: Curve> {
    /// Compressed curve point
    Compressed {
        /// x-coordinate
        x: &'a FieldBytes<C>,

        /// Is the y-coordinate odd?
        y_is_odd: bool,
    },

    /// Uncompressed curve point
    Uncompressed {
        /// x-coordinate
        x: &'a FieldBytes<C>,

        /// y-coordinate
        y: &'a FieldBytes<C>,
    },
}

/// Trait for deserializing a value from a SEC1 encoded curve point.
///
/// This is intended for use with the `AffinePoint` type for a given elliptic curve.
pub trait FromEncodedPoint<C>
where
    C: Curve,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
    Self: Sized,
{
    /// Deserialize the type this trait is impl'd on from an [`EncodedPoint`].
    ///
    /// # Returns
    ///
    /// `None` if the [`EncodedPoint`] is invalid.
    fn from_encoded_point(public_key: &EncodedPoint<C>) -> CtOption<Self>;
}

/// Trait for serializing a value to a SEC1 encoded curve point.
///
/// This is intended for use with the `AffinePoint` type for a given elliptic curve.
pub trait ToEncodedPoint<C>
where
    C: Curve,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// Serialize this value as a SEC1 [`EncodedPoint`], optionally applying
    /// point compression.
    fn to_encoded_point(&self, compress: bool) -> EncodedPoint<C>;
}

/// Tag byte used by the `Elliptic-Curve-Point-to-Octet-String` encoding.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Tag {
    /// Compressed point with even y-coordinate (`0x02`)
    CompressedEvenY = 2,

    /// Compressed point with odd y-coordinate (`0x03`)
    CompressedOddY = 3,

    /// Uncompressed point (`0x04`)
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

    /// Is this point compressed?
    pub fn is_compressed(self) -> bool {
        match self {
            Tag::CompressedEvenY | Tag::CompressedOddY => true,
            Tag::Uncompressed => false,
        }
    }

    /// Compute the expected total message length for a message prefixed
    /// with this tag (including the tag byte), given the field element size
    /// (in bytes) for a particular elliptic curve.
    pub fn message_len(self, field_element_size: usize) -> usize {
        1 + if self.is_compressed() {
            field_element_size
        } else {
            field_element_size * 2
        }
    }

    /// Compress the given y-coordinate, returning a `Tag::Compressed*` value
    fn compress_y(y: &[u8]) -> Self {
        debug_assert!(!y.is_empty());

        // Is the y-coordinate odd in the SEC1 sense: `self mod 2 == 1`?
        if y.as_ref().last().unwrap() & 1 == 1 {
            Tag::CompressedOddY
        } else {
            Tag::CompressedEvenY
        }
    }
}

impl From<Tag> for u8 {
    fn from(tag: Tag) -> u8 {
        tag as u8
    }
}

#[cfg(test)]
mod tests {
    use super::{Coordinates, Tag};
    use crate::{weierstrass, Curve};
    use generic_array::{typenum::U32, GenericArray};
    use hex_literal::hex;

    #[derive(Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
    struct ExampleCurve;

    impl Curve for ExampleCurve {
        type FieldSize = U32;
    }

    impl weierstrass::Curve for ExampleCurve {}

    type EncodedPoint = super::EncodedPoint<ExampleCurve>;

    /// Example uncompressed point
    const UNCOMPRESSED_BYTES: [u8; 65] = hex!("0411111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222");

    /// Example compressed point: `UNCOMPRESSED_BYTES` after point compression
    const COMPRESSED_BYTES: [u8; 33] =
        hex!("021111111111111111111111111111111111111111111111111111111111111111");

    #[test]
    fn decode_compressed_point() {
        // Even y-coordinate
        let compressed_even_y_bytes =
            hex!("020100000000000000000000000000000000000000000000000000000000000000");

        let compressed_even_y = EncodedPoint::from_bytes(&compressed_even_y_bytes[..]).unwrap();

        assert!(compressed_even_y.is_compressed());
        assert_eq!(compressed_even_y.tag(), Tag::CompressedEvenY);
        assert_eq!(compressed_even_y.len(), 33);
        assert_eq!(compressed_even_y.as_bytes(), &compressed_even_y_bytes[..]);

        assert_eq!(
            compressed_even_y.coordinates(),
            Coordinates::Compressed {
                x: &hex!("0100000000000000000000000000000000000000000000000000000000000000").into(),
                y_is_odd: false
            }
        );

        assert_eq!(
            compressed_even_y.x(),
            &hex!("0100000000000000000000000000000000000000000000000000000000000000").into()
        );
        assert_eq!(compressed_even_y.y(), None);

        // Odd y-coordinate
        let compressed_odd_y_bytes =
            hex!("030200000000000000000000000000000000000000000000000000000000000000");

        let compressed_odd_y = EncodedPoint::from_bytes(&compressed_odd_y_bytes[..]).unwrap();

        assert!(compressed_odd_y.is_compressed());
        assert_eq!(compressed_odd_y.tag(), Tag::CompressedOddY);
        assert_eq!(compressed_odd_y.len(), 33);
        assert_eq!(compressed_odd_y.as_bytes(), &compressed_odd_y_bytes[..]);

        assert_eq!(
            compressed_odd_y.coordinates(),
            Coordinates::Compressed {
                x: &hex!("0200000000000000000000000000000000000000000000000000000000000000").into(),
                y_is_odd: true
            }
        );

        assert_eq!(
            compressed_odd_y.x(),
            &hex!("0200000000000000000000000000000000000000000000000000000000000000").into()
        );
        assert_eq!(compressed_odd_y.y(), None);
    }

    #[test]
    fn decode_uncompressed_point() {
        let uncompressed_point = EncodedPoint::from_bytes(&UNCOMPRESSED_BYTES[..]).unwrap();

        assert!(!uncompressed_point.is_compressed());
        assert_eq!(uncompressed_point.tag(), Tag::Uncompressed);
        assert_eq!(uncompressed_point.len(), 65);
        assert_eq!(uncompressed_point.as_bytes(), &UNCOMPRESSED_BYTES[..]);

        assert_eq!(
            uncompressed_point.coordinates(),
            Coordinates::Uncompressed {
                x: &hex!("1111111111111111111111111111111111111111111111111111111111111111").into(),
                y: &hex!("2222222222222222222222222222222222222222222222222222222222222222").into()
            }
        );

        assert_eq!(
            uncompressed_point.x(),
            &hex!("1111111111111111111111111111111111111111111111111111111111111111").into()
        );
        assert_eq!(
            uncompressed_point.y().unwrap(),
            &hex!("2222222222222222222222222222222222222222222222222222222222222222").into()
        );
    }

    #[test]
    fn decode_invalid_tag() {
        let mut compressed_bytes = COMPRESSED_BYTES.clone();
        let mut uncompressed_bytes = UNCOMPRESSED_BYTES.clone();

        for bytes in &mut [&mut compressed_bytes[..], &mut uncompressed_bytes[..]] {
            for tag in 0..=0xFF {
                // valid tags
                if tag == 2 || tag == 3 || tag == 4 {
                    continue;
                }

                (*bytes)[0] = tag;
                let decode_result = EncodedPoint::from_bytes(&*bytes);
                assert!(decode_result.is_err());
            }
        }
    }

    #[test]
    fn decode_truncated_point() {
        for bytes in &[&COMPRESSED_BYTES[..], &UNCOMPRESSED_BYTES[..]] {
            for len in 0..bytes.len() {
                let decode_result = EncodedPoint::from_bytes(&bytes[..len]);
                assert!(decode_result.is_err());
            }
        }
    }

    #[test]
    fn from_untagged_point() {
        let untagged_bytes = hex!("11111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222");
        let uncompressed_point =
            EncodedPoint::from_untagged_bytes(GenericArray::from_slice(&untagged_bytes[..]));
        assert_eq!(uncompressed_point.as_bytes(), &UNCOMPRESSED_BYTES[..]);
    }

    #[test]
    fn from_affine_coordinates() {
        let x = hex!("1111111111111111111111111111111111111111111111111111111111111111");
        let y = hex!("2222222222222222222222222222222222222222222222222222222222222222");

        let uncompressed_point = EncodedPoint::from_affine_coordinates(&x.into(), &y.into(), false);
        assert_eq!(uncompressed_point.as_bytes(), &UNCOMPRESSED_BYTES[..]);

        let compressed_point = EncodedPoint::from_affine_coordinates(&x.into(), &y.into(), true);
        assert_eq!(compressed_point.as_bytes(), &COMPRESSED_BYTES[..]);
    }

    #[test]
    fn compress() {
        let uncompressed_point = EncodedPoint::from_bytes(&UNCOMPRESSED_BYTES[..]).unwrap();
        let compressed_point = uncompressed_point.compress();
        assert_eq!(compressed_point.as_bytes(), &COMPRESSED_BYTES[..]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn to_bytes() {
        let uncompressed_point = EncodedPoint::from_bytes(&UNCOMPRESSED_BYTES[..]).unwrap();
        assert_eq!(&*uncompressed_point.to_bytes(), &UNCOMPRESSED_BYTES[..]);
    }
}
