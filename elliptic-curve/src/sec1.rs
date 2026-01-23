//! Support for SEC1 elliptic curve encoding formats.
//!
//! <https://www.secg.org/sec1-v2.pdf>

pub use sec1::point::{Coordinates, ModulusSize, Tag};

use crate::{Curve, Error, FieldBytesSize, Result, SecretKey, array::Array, ctutils::CtOption};

#[cfg(feature = "arithmetic")]
use crate::{AffinePoint, CurveArithmetic};
#[cfg(feature = "alloc")]
use {crate::point::PointCompression, alloc::boxed::Box};

/// Encoded elliptic curve point with point compression.
pub type CompressedPoint<C> = Array<u8, CompressedPointSize<C>>;

/// Size of a compressed elliptic curve point.
pub type CompressedPointSize<C> = <FieldBytesSize<C> as ModulusSize>::CompressedPointSize;

/// Encoded elliptic curve point sized appropriately for a given curve.
pub type EncodedPoint<C> = ::sec1::point::EncodedPoint<FieldBytesSize<C>>;

/// Encoded elliptic curve point *without* point compression.
pub type UncompressedPoint<C> = Array<u8, UncompressedPointSize<C>>;

/// Size of an uncompressed elliptic curve point.
pub type UncompressedPointSize<C> = <FieldBytesSize<C> as ModulusSize>::UncompressedPointSize;

/// Decode curve point using the `Octet-String-to-Elliptic-Curve-Point` conversion described in
/// [SEC 1: Elliptic Curve Cryptography (Version 2.0)](https://www.secg.org/sec1-v2.pdf)
/// §2.3.4 (page 11).
pub trait FromEncodedPoint<C>
where
    Self: Sized,
    C: Curve,
    FieldBytesSize<C>: ModulusSize,
{
    /// Decode curve point from a SEC1 [`EncodedPoint`].
    fn from_encoded_point(point: &EncodedPoint<C>) -> CtOption<Self>;

    /// Decode curve point from the provided SEC1 encoding (compressed, uncompressed, or
    /// identity) using the `Octet-String-to-Elliptic-Curve-Point` conversion.
    fn from_sec1_bytes(bytes: &[u8]) -> Result<Self> {
        let point = EncodedPoint::<C>::from_bytes(bytes)?;
        Self::from_encoded_point(&point).into_option().ok_or(Error)
    }
}

/// Encode curve point using the `Elliptic-Curve-Point-to-Octet-String` conversion described in
/// [SEC 1: Elliptic Curve Cryptography (Version 2.0)](https://www.secg.org/sec1-v2.pdf)
/// §2.3.3 (page 10).
pub trait ToEncodedPoint<C>
where
    C: Curve,
    FieldBytesSize<C>: ModulusSize,
{
    /// Serialize curve point as a SEC1 [`EncodedPoint`], optionally applying point compression
    /// according to the `compress` flag.
    fn to_encoded_point(&self, compress: bool) -> EncodedPoint<C>;

    /// Serialize curve point as a [`CompressedPoint`].
    fn to_compressed_point(&self) -> CompressedPoint<C> {
        let mut ret = CompressedPoint::<C>::default();
        ret.copy_from_slice(self.to_encoded_point(true).as_bytes());
        ret
    }

    /// Serialize curve point as a [`CompressedPoint`].
    fn to_uncompressed_point(&self) -> UncompressedPoint<C> {
        let mut ret = UncompressedPoint::<C>::default();
        ret.copy_from_slice(self.to_encoded_point(false).as_bytes());
        ret
    }

    /// Encode curve point using the `Elliptic-Curve-Point-to-Octet-String` conversion and the
    /// point compression default for this curve as specified by the [`PointCompression`] trait.
    #[cfg(feature = "alloc")]
    fn to_sec1_bytes(&self) -> Box<[u8]>
    where
        C: PointCompression,
    {
        self.to_encoded_point(C::COMPRESS_POINTS).to_bytes()
    }
}

/// Trait for serializing a value to a SEC1 encoded curve point with compaction.
///
/// This is intended for use with the `AffinePoint` type for a given elliptic curve.
pub trait ToCompactEncodedPoint<C>
where
    C: Curve,
    FieldBytesSize<C>: ModulusSize,
{
    /// Serialize this value as a SEC1 [`EncodedPoint`], optionally applying
    /// point compression.
    fn to_compact_encoded_point(&self) -> CtOption<EncodedPoint<C>>;
}

/// Validate that the given [`EncodedPoint`] represents the encoded public key
/// value of the given secret.
///
/// Curve implementations which also impl [`CurveArithmetic`] will receive
/// a blanket default impl of this trait.
pub trait ValidatePublicKey
where
    Self: Curve,
    FieldBytesSize<Self>: ModulusSize,
{
    /// Validate that the given [`EncodedPoint`] is a valid public key for the
    /// provided secret value.
    #[allow(unused_variables)]
    fn validate_public_key(
        secret_key: &SecretKey<Self>,
        public_key: &EncodedPoint<Self>,
    ) -> Result<()> {
        // Provide a default "always succeeds" implementation.
        // This is the intended default for curve implementations which
        // do not provide an arithmetic implementation, since they have no
        // way to verify this.
        //
        // Implementations with an arithmetic impl will receive a blanket impl
        // of this trait.
        Ok(())
    }
}

#[cfg(feature = "arithmetic")]
impl<C> ValidatePublicKey for C
where
    C: CurveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    fn validate_public_key(secret_key: &SecretKey<C>, public_key: &EncodedPoint<C>) -> Result<()> {
        let pk = secret_key
            .public_key()
            .to_encoded_point(public_key.is_compressed());

        if public_key == &pk {
            Ok(())
        } else {
            Err(Error)
        }
    }
}
