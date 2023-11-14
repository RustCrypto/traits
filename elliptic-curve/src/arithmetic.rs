//! Elliptic curve arithmetic traits.

use crate::{
    ops::{Invert, LinearCombination, MulByGenerator, Reduce, ShrAssign},
    point::AffineCoordinates,
    scalar::{FromUintUnchecked, IsHigh},
    Curve, FieldBytes, PrimeCurve, ScalarPrimitive,
};
use core::fmt::Debug;
use subtle::{ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::DefaultIsZeroes;

/// Elliptic curve with an arithmetic implementation.
pub trait CurveArithmetic: Curve {
    /// Elliptic curve point in affine coordinates.
    type AffinePoint: 'static
        + AffineCoordinates<FieldRepr = FieldBytes<Self>>
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
    type Scalar: AsRef<Self::Scalar>
        + DefaultIsZeroes
        + From<ScalarPrimitive<Self>>
        + FromUintUnchecked<Uint = Self::Uint>
        + Into<FieldBytes<Self>>
        + Into<ScalarPrimitive<Self>>
        + Into<Self::Uint>
        + Invert<Output = CtOption<Self::Scalar>>
        + IsHigh
        + PartialOrd
        + Reduce<Self::Uint, Bytes = FieldBytes<Self>>
        + ShrAssign<usize>
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

/// Normalize point(s) in projective representation by converting them to their affine ones.
pub trait BatchNormalize<Points>: group::Curve {
    /// The output of the batch normalization; a container of affine points.
    type Output: AsRef<Self::AffineRepr>;

    /// Perform a batched conversion to affine representation on a sequence of projective points
    /// at an amortized cost that should be practically as efficient as a single conversion.
    /// Internally, implementors should rely upon `InvertBatch`.
    fn batch_normalize(points: Points) -> <Self as BatchNormalize<Points>>::Output;
}
