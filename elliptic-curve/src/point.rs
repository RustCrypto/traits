//! Elliptic curve points.

use crate::{Curve, FieldBytes, Scalar};

/// Elliptic curve with projective arithmetic implementation.
pub trait ProjectiveArithmetic: Curve
where
    FieldBytes<Self>: From<Scalar<Self>> + for<'r> From<&'r Scalar<Self>>,
    Scalar<Self>: ff::PrimeField<Repr = FieldBytes<Self>>,
{
    /// Elliptic curve point in projective coordinates.
    type ProjectivePoint: group::Curve;
}

/// Affine point type for a given curve with a [`ProjectiveArithmetic`]
/// implementation.
pub type AffinePoint<C> =
    <<C as ProjectiveArithmetic>::ProjectivePoint as group::Curve>::AffineRepr;

/// Projective point type for a given curve with a [`ProjectiveArithmetic`]
/// implementation.
pub type ProjectivePoint<C> = <C as ProjectiveArithmetic>::ProjectivePoint;
