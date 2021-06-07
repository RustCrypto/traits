//! Elliptic curve arithmetic traits.

use crate::{Curve, FieldBytes};
use core::fmt::Debug;
use subtle::{ConditionallySelectable, ConstantTimeEq};

/// Elliptic curve with affine arithmetic implementation.
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub trait AffineArithmetic: Curve + ScalarArithmetic {
    /// Elliptic curve point in affine coordinates.
    type AffinePoint: Copy
        + Clone
        + ConditionallySelectable
        + ConstantTimeEq
        + Debug
        + Default
        + Sized
        + Send
        + Sync
        + 'static;
}

/// Elliptic curve with projective arithmetic implementation.
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub trait ProjectiveArithmetic: Curve + AffineArithmetic {
    /// Elliptic curve point in projective coordinates.
    ///
    /// Note: the following bounds are enforced by [`group::Group`]:
    /// - `Copy`
    /// - `Clone`
    /// - `Debug`
    /// - `Eq`
    /// - `Sized`
    /// - `Send`
    /// - `Sync`
    type ProjectivePoint: ConditionallySelectable
        + ConstantTimeEq
        + Default
        + From<Self::AffinePoint>
        + Into<Self::AffinePoint>
        + group::Curve<AffineRepr = Self::AffinePoint>
        + group::Group<Scalar = Self::Scalar>;
}

/// Scalar arithmetic.
#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub trait ScalarArithmetic: Curve {
    /// Scalar field type.
    ///
    /// Note: the following bounds are enforced by [`ff::Field`]:
    /// - `Copy`
    /// - `Clone`
    /// - `ConditionallySelectable`
    /// - `Debug`
    /// - `Default`
    /// - `Send`
    /// - `Sync`
    type Scalar: ConstantTimeEq + ff::Field + ff::PrimeField<Repr = FieldBytes<Self>>;
}
