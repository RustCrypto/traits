//! Support for SEC1 elliptic curve encoding formats.
//!
//! <https://www.secg.org/sec1-v2.pdf>

mod ec_private_key;
mod encoded_point;

pub use self::encoded_point::{
    CompressedPointSize, Coordinates, EncodedPoint, UncompressedPointSize, UntaggedPointSize,
};

pub(crate) use self::ec_private_key::EcPrivateKey;

use crate::{PrimeCurve, Result, SecretKey};
use core::ops::Add;
use generic_array::{typenum::U1, ArrayLength};

#[cfg(feature = "arithmetic")]
use crate::{AffinePoint, Error, ProjectiveArithmetic};

/// Trait for deserializing a value from a SEC1 encoded curve point.
///
/// This is intended for use with the `AffinePoint` type for a given elliptic curve.
pub trait FromEncodedPoint<C>
where
    Self: Sized,
    C: PrimeCurve,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// Deserialize the type this trait is impl'd on from an [`EncodedPoint`].
    ///
    /// # Returns
    ///
    /// `None` if the [`EncodedPoint`] is invalid.
    fn from_encoded_point(public_key: &EncodedPoint<C>) -> Option<Self>;
}

/// Trait for serializing a value to a SEC1 encoded curve point.
///
/// This is intended for use with the `AffinePoint` type for a given elliptic curve.
pub trait ToEncodedPoint<C>
where
    C: PrimeCurve,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// Serialize this value as a SEC1 [`EncodedPoint`], optionally applying
    /// point compression.
    fn to_encoded_point(&self, compress: bool) -> EncodedPoint<C>;
}

/// Trait for serializing a value to a SEC1 encoded curve point with compaction.
///
/// This is intended for use with the `AffinePoint` type for a given elliptic curve.
pub trait ToCompactEncodedPoint<C>
where
    C: PrimeCurve,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// Serialize this value as a SEC1 [`EncodedPoint`], optionally applying
    /// point compression.
    fn to_compact_encoded_point(&self) -> Option<EncodedPoint<C>>;
}

/// Validate that the given [`EncodedPoint`] represents the encoded public key
/// value of the given secret.
///
/// Curve implementations which also impl [`ProjectiveArithmetic`] will receive
/// a blanket default impl of this trait.
pub trait ValidatePublicKey
where
    Self: PrimeCurve,
    UntaggedPointSize<Self>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<Self>: ArrayLength<u8>,
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

#[cfg(all(feature = "arithmetic"))]
impl<C> ValidatePublicKey for C
where
    C: PrimeCurve + ProjectiveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
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
