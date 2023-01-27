use super::FromUintUnchecked;
use crate::{CurveArithmetic, Scalar};
use ff::{Field, PrimeField};
use subtle::CtOption;

/// Fast variable-time inversion using Stein's algorithm.
///
/// Returns none if the scalar is zero.
///
/// <https://link.springer.com/article/10.1007/s13389-016-0135-4>
#[allow(non_snake_case)]
pub fn invert_vartime<C>(scalar: &Scalar<C>) -> CtOption<Scalar<C>>
where
    C: CurveArithmetic,
{
    let order_div_2 = Scalar::<C>::from_uint_unchecked(C::ORDER >> 1);

    let mut u = *scalar;
    let mut v = Scalar::<C>::from_uint_unchecked(C::ORDER); // note: technically invalid
    let mut A = Scalar::<C>::ONE;
    let mut C = Scalar::<C>::ZERO;

    while !bool::from(u.is_zero()) {
        // u-loop
        while bool::from(u.is_even()) {
            u >>= 1;

            let was_odd: bool = A.is_odd().into();
            A >>= 1;

            if was_odd {
                A += order_div_2;
                A += Scalar::<C>::ONE;
            }
        }

        // v-loop
        while bool::from(v.is_even()) {
            v >>= 1;

            let was_odd: bool = C.is_odd().into();
            C >>= 1;

            if was_odd {
                C += order_div_2;
                C += Scalar::<C>::ONE;
            }
        }

        // sub-step
        if u < v {
            v -= &u;
            C -= &A;
        } else {
            u -= &v;
            A -= &C;
        }
    }

    CtOption::new(C, !scalar.is_zero())
}
