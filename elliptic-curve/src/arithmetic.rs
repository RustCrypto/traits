//! Elliptic curve arithmetic traits.

use crate::{
    ops::{LinearCombination, MulByGenerator},
    AffineXCoordinate, AffineYIsOdd, Curve, FieldBytes, IsHigh, PrimeCurve, ScalarCore,
};
use core::fmt::Debug;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::DefaultIsZeroes;

/// Elliptic curve with an arithmetic implementation.
pub trait CurveArithmetic: Curve {
    /// Elliptic curve point in affine coordinates.
    type AffinePoint: 'static
        + AffineXCoordinate<FieldRepr = FieldBytes<Self>>
        + AffineYIsOdd
        + Copy
        + ConditionallySelectable
        + ConstantTimeEq
        + Debug
        + Default
        + DefaultIsZeroes
        + Eq
        + PartialEq
        + Sized
        + Send
        + Sync;

    /// Elliptic curve point in projective coordinates.
    ///
    /// Note: the following bounds are provided by [`group::Group`]:
    /// - `'static`
    /// - [`Copy`]
    /// - [`Clone`]
    /// - [`Debug`]
    /// - [`Eq`]
    /// - [`Sized`]
    /// - [`Send`]
    /// - [`Sync`]
    type ProjectivePoint: ConditionallySelectable
        + ConstantTimeEq
        + Default
        + DefaultIsZeroes
        + From<Self::AffinePoint>
        + Into<Self::AffinePoint>
        + LinearCombination
        + MulByGenerator
        + group::Curve<AffineRepr = Self::AffinePoint>
        + group::Group<Scalar = Self::Scalar>;

    /// Scalar field modulo this curve's order.
    ///
    /// Note: the following bounds are provided by [`ff::Field`]:
    /// - `'static`
    /// - [`Copy`]
    /// - [`Clone`]
    /// - [`ConditionallySelectable`]
    /// - [`ConstantTimeEq`]
    /// - [`Debug`]
    /// - [`Default`]
    /// - [`Send`]
    /// - [`Sync`]
    type Scalar: DefaultIsZeroes
        + From<ScalarCore<Self>>
        + Into<FieldBytes<Self>>
        + Into<Self::Uint>
        + IsHigh
        + ff::Field
        + ff::PrimeField<Repr = FieldBytes<Self>>;
}

/// Prime order elliptic curve with projective arithmetic implementation.
pub trait PrimeCurveArithmetic:
    PrimeCurve + CurveArithmetic<ProjectivePoint = Self::CurveGroup>
{
    /// Prime order elliptic curve group.
    type CurveGroup: group::prime::PrimeCurve<Affine = <Self as CurveArithmetic>::AffinePoint>;
}
