//! Elliptic curve points.

use crate::{Curve, ScalarArithmetic};

/// Elliptic curve with projective arithmetic implementation.
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub trait ProjectiveArithmetic: Curve + ScalarArithmetic {
    /// Elliptic curve point in projective coordinates.
    type ProjectivePoint: group::Curve + group::Group<Scalar = Self::Scalar>;
}

/// Affine point type for a given curve with a [`ProjectiveArithmetic`]
/// implementation.
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub type AffinePoint<C> =
    <<C as ProjectiveArithmetic>::ProjectivePoint as group::Curve>::AffineRepr;

/// Projective point type for a given curve with a [`ProjectiveArithmetic`]
/// implementation.
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub type ProjectivePoint<C> = <C as ProjectiveArithmetic>::ProjectivePoint;
