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

/// Encoded elliptic curve point *without* point compression.
pub type UncompressedPoint<C> = Array<u8, UncompressedPointSize<C>>;

/// Size of an uncompressed elliptic curve point.
pub type UncompressedPointSize<C> = <FieldBytesSize<C> as ModulusSize>::UncompressedPointSize;

/// SEC1-encoded elliptic curve point sized appropriately for a given curve.
pub type Sec1Point<C> = ::sec1::point::EncodedPoint<FieldBytesSize<C>>;

/// DEPRECATED: legacy name for [`Sec1Point`].
#[deprecated(since = "0.14.0", note = "use `Sec1Point` instead")]
pub type EncodedPoint<C> = Sec1Point<C>;

/// Decode curve point using the `Octet-String-to-Elliptic-Curve-Point` conversion described in
/// [SEC 1: Elliptic Curve Cryptography (Version 2.0)](https://www.secg.org/sec1-v2.pdf)
/// §2.3.4 (page 11).
pub trait FromSec1Point<C>
where
    Self: Sized,
    C: Curve,
    FieldBytesSize<C>: ModulusSize,
{
    /// Decode curve point from a SEC1 [`Sec1Point`].
    fn from_sec1_point(point: &Sec1Point<C>) -> CtOption<Self>;

    /// Decode curve point from the provided SEC1 encoding (compressed, uncompressed, or
    /// identity) using the `Octet-String-to-Elliptic-Curve-Point` conversion.
    fn from_sec1_bytes(bytes: &[u8]) -> Result<Self> {
        let point = Sec1Point::<C>::from_bytes(bytes)?;
        Self::from_sec1_point(&point).into_option().ok_or(Error)
    }

    /// DEPRECATED: legacy name for [`FromSec1Point::from_sec1_point`].
    #[deprecated(
        since = "0.14.0",
        note = "use `FromSec1Point::from_sec1_point` instead"
    )]
    fn from_encoded_point(point: &Sec1Point<C>) -> CtOption<Self> {
        Self::from_sec1_point(point)
    }
}

/// Encode curve point using the `Elliptic-Curve-Point-to-Octet-String` conversion described in
/// [SEC 1: Elliptic Curve Cryptography (Version 2.0)](https://www.secg.org/sec1-v2.pdf)
/// §2.3.3 (page 10).
pub trait ToSec1Point<C>
where
    C: Curve,
    FieldBytesSize<C>: ModulusSize,
{
    /// Serialize curve point as a SEC1 [`Sec1Point`], optionally applying point compression
    /// according to the `compress` flag.
    fn to_sec1_point(&self, compress: bool) -> Sec1Point<C>;

    /// Encode curve point using the `Elliptic-Curve-Point-to-Octet-String` conversion and the
    /// point compression default for this curve as specified by the [`PointCompression`] trait.
    #[cfg(feature = "alloc")]
    fn to_sec1_bytes(&self) -> Box<[u8]>
    where
        C: PointCompression,
    {
        self.to_sec1_point(C::COMPRESS_POINTS).to_bytes()
    }

    /// Serialize curve point as a [`CompressedPoint`].
    fn to_compressed_point(&self) -> CompressedPoint<C> {
        let mut ret = CompressedPoint::<C>::default();
        ret.copy_from_slice(self.to_sec1_point(true).as_bytes());
        ret
    }

    /// Serialize curve point as a [`CompressedPoint`].
    fn to_uncompressed_point(&self) -> UncompressedPoint<C> {
        let mut ret = UncompressedPoint::<C>::default();
        ret.copy_from_slice(self.to_sec1_point(false).as_bytes());
        ret
    }

    /// DEPRECATED: legacy name for [`ToSec1Point::to_sec1_point`].
    #[deprecated(since = "0.14.0", note = "use `ToSec1Point::to_sec1_point` instead")]
    fn to_encoded_point(&self, compress: bool) -> Sec1Point<C> {
        self.to_sec1_point(compress)
    }
}

/// DEPRECATED: stub trait to help discover the new name for [`FromSec1Point`].
#[deprecated(since = "0.14.0", note = "use `FromSec1Point` instead")]
pub trait FromEncodedPoint<C>: FromSec1Point<C>
where
    Self: Sized,
    C: Curve,
    FieldBytesSize<C>: ModulusSize,
{
}

#[allow(deprecated)]
impl<P, C> FromEncodedPoint<C> for P
where
    Self: FromSec1Point<C> + Sized,
    C: Curve,
    FieldBytesSize<C>: ModulusSize,
{
}

/// DEPRECATED: stub trait to help discover the new name for [`ToSec1Point`].
#[deprecated(since = "0.14.0", note = "use `ToSec1Point` instead")]
pub trait ToEncodedPoint<C>: ToSec1Point<C>
where
    C: Curve,
    FieldBytesSize<C>: ModulusSize,
{
}

#[allow(deprecated)]
impl<T, C> ToEncodedPoint<C> for T
where
    Self: ToSec1Point<C>,
    C: Curve,
    FieldBytesSize<C>: ModulusSize,
{
}

/// Trait for serializing a value to a SEC1 encoded curve point with compaction.
///
/// This is intended for use with the `AffinePoint` type for a given elliptic curve.
pub trait ToCompactSec1Point<C>
where
    C: Curve,
    FieldBytesSize<C>: ModulusSize,
{
    /// Serialize this value as a SEC1 [`Sec1Point`], optionally applying
    /// point compression.
    fn to_compact_encoded_point(&self) -> CtOption<Sec1Point<C>>;
}

/// Validate that the given [`Sec1Point`] represents the encoded public key
/// value of the given secret.
///
/// Curve implementations which also impl [`CurveArithmetic`] will receive
/// a blanket default impl of this trait.
pub trait ValidatePublicKey
where
    Self: Curve,
    FieldBytesSize<Self>: ModulusSize,
{
    /// Validate that the given [`Sec1Point`] is a valid public key for the
    /// provided secret value.
    #[allow(unused_variables)]
    fn validate_public_key(
        secret_key: &SecretKey<Self>,
        public_key: &Sec1Point<Self>,
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
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    fn validate_public_key(secret_key: &SecretKey<C>, public_key: &Sec1Point<C>) -> Result<()> {
        let pk = secret_key
            .public_key()
            .to_sec1_point(public_key.is_compressed());

        if public_key == &pk {
            Ok(())
        } else {
            Err(Error)
        }
    }
}
