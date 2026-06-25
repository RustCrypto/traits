//! Traits for arithmetic operations on elliptic curve field elements.

pub use bigint::{Invert, Reduce, modular::Retrieve};
pub use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Shr, ShrAssign, Sub, SubAssign};

use crate::CurveGroup;
use ff::{BatchInverter, Field};
use group::Group;

/// Perform a batched inversion on a slice of field elements (i.e. base field elements or scalars)
/// at an amortized cost that should be practically as efficient as a single inversion, writing
/// the field element inversions into `element`, and utilizing `scratch` as temporary storage.
///
/// Note: the [`ff`] crate also provides [`ff::BatchInvert`], however that trait has a hard
/// requirement on `alloc` whereas this one is always available, even in `no_alloc` contexts.
///
/// # Panics
/// If `elements` and `scratch` are not the same length.
pub trait BatchInvert: Field {
    /// Inverts each field element in `elements` (when non-zero). Zero-valued elements are
    /// left as zero.
    ///
    /// `scratch_space` is a slice of field elements that can be freely overwritten.
    ///
    /// Returns the inverse of the product of all non-zero field elements.
    ///
    /// # Panics
    /// If `elements.len() != scratch_space.len()`.
    fn batch_invert_in_place(elements: &mut [Self], scratch_space: &mut [Self]) -> Self {
        BatchInverter::invert_with_external_scratch(elements, scratch_space)
    }

    /// Variable-time batch inversion.
    ///
    /// <div class="warning">
    /// <b>Security Warning</b>
    ///
    /// This should NOT be used on secret values!
    /// </b>
    fn batch_invert_in_place_vartime(elements: &mut [Self], scratch_space: &mut [Self]) -> Self {
        // Call the constant-time implementation by default
        Self::batch_invert_in_place(elements, scratch_space)
    }
}

/// Perform a doubling (i.e. `self + self`).
pub trait Double: Sized {
    /// Double this value, returning the doubled result.
    #[must_use]
    fn double(&self) -> Self;

    /// Double this value in-place, assigning `self + self` to `self`.
    #[inline]
    fn double_in_place(&mut self) {
        *self = self.double();
    }
}

/// Linear combination.
///
/// This trait enables optimized implementations of linear combinations (e.g. Shamir's Trick).
///
/// It's generic around `PointsAndScalars` to allow overlapping impls. For example, const generic
/// impls can use the input size to determine the size needed to store temporary variables.
pub trait LinearCombination<PointsAndScalars>: CurveGroup
where
    PointsAndScalars: AsRef<[(Self, Self::Scalar)]> + ?Sized,
{
    /// Calculates `x1 * k1 + ... + xn * kn`.
    fn lincomb(points_and_scalars: &PointsAndScalars) -> Self {
        points_and_scalars
            .as_ref()
            .iter()
            .copied()
            .map(|(point, scalar)| point * scalar)
            .sum()
    }

    /// Calculates `x1 * k1 + ... + xn * kn`.
    ///
    /// This is equivalent to [`LinearCombination::lincomb`] except
    /// that it may leak the value of the points and/or scalars due to
    /// variable-time behavior.
    fn lincomb_vartime(points_and_scalars: &PointsAndScalars) -> Self {
        Self::lincomb(points_and_scalars)
    }
}

/// Variable-time equivalent of the [`Mul`] trait.
///
/// Should always compute the same results as [`Mul`], but may provide a faster implementation.
///
/// <div class="warning">
/// <b>Security Warning</b>
///
/// Variable-time operations should only be used on non-secret values, and may potentially leak
/// secret values!
/// </div>
pub trait MulVartime<Rhs = Self>: Mul<Rhs> {
    /// Multiply `self` by `rhs` in variable-time.
    fn mul_vartime(self, rhs: Rhs) -> <Self as Mul<Rhs>>::Output;
}

/// Variable-time multiplication by the generator of the curve group.
///
/// <div class="warning">
/// <b>Security Warning</b>
///
/// Variable-time operations should only be used on non-secret values, and may potentially leak
/// secret values!
/// </div>
pub trait MulByGeneratorVartime: Group + for<'a> MulVartime<&'a Self::Scalar> {
    /// Multiply by the generator of the prime-order subgroup.
    ///
    /// Variable-time equivalent of [`Group::mul_by_generator`].
    fn mul_by_generator_vartime(scalar: &Self::Scalar) -> Self {
        Self::generator().mul_vartime(scalar)
    }

    /// Multiply `a` by the generator of the prime-order subgroup, adding the result to the point
    /// `P` multiplied by the scalar `b`, i.e. compute `aG + bP`.
    ///
    /// This operation is the core of many signature verification algorithms.
    fn mul_by_generator_and_mul_add_vartime(a: &Self::Scalar, b: &Self::Scalar, p: &Self) -> Self {
        Self::mul_by_generator_vartime(a) + p.mul_vartime(b)
    }
}

/// Modular reduction to a non-zero output.
///
/// This trait is primarily intended for use by curve implementations such
/// as the `k256` and `p256` crates.
///
/// End users should use the [`Reduce`] impl on
/// [`NonZeroScalar`][`crate::NonZeroScalar`] instead.
pub trait ReduceNonZero<T>: Reduce<T> {
    /// Perform a modular reduction, returning a field element.
    fn reduce_nonzero(n: &T) -> Self;
}
