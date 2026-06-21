//! Traits for arithmetic operations on elliptic curve field elements.

pub use bigint::{Invert, Reduce};
pub use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Shr, ShrAssign, Sub, SubAssign};

use crate::CurveGroup;
use ff::Field;
use group::Group;
use subtle::Choice;

/// Perform a batched inversion on a slice of field elements (i.e. base field elements or scalars)
/// at an amortized cost that should be practically as efficient as a single inversion, writing
/// the field element inversions into `element`, and utilizing `scratch` as temporary storage.
///
/// # Panics
/// If `elements` and `scratch` are not the same length.
pub trait BatchInvert: Field {
    /// Invert a batch of field elements.
    ///
    /// Returns the falsy [`Choice`] in the event any of the elements is `0`.
    fn batch_invert_in_place(elements: &mut [Self], scratch: &mut [Self]) -> Choice {
        // Implements "Montgomery's trick", a trick for computing many modular inverses at once.
        //
        // "Montgomery's trick" works by reducing the problem of computing `n` inverses
        // to computing a single inversion, plus some storage and `O(n)` extra multiplications.
        //
        // See: https://iacr.org/archive/pkc2004/29470042/29470042.pdf section 2.2.
        assert_eq!(elements.len(), scratch.len());

        let mut acc = Self::ONE;
        let mut all_nonzero = Choice::from(1u8);

        for (tmp, e) in scratch.iter_mut().zip(elements.iter()) {
            // $ a_n = a_{n-1}*x_n $
            *tmp = acc;
            let is_zero = e.ct_eq(&Self::ZERO);
            all_nonzero &= !is_zero;
            acc = Self::conditional_select(&(acc * e), &acc, is_zero);
        }

        // `acc` is the product of every nonzero element, so this can't fail.
        acc = acc.invert().unwrap_or(Self::ONE);

        for (e, tmp) in elements.iter_mut().zip(scratch.iter()).rev() {
            let is_zero = e.ct_eq(&Self::ZERO);
            let new_acc = Self::conditional_select(&(acc * *e), &acc, is_zero);
            *e = Self::conditional_select(&(acc * *tmp), e, is_zero);
            acc = new_acc;
        }

        all_nonzero
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
