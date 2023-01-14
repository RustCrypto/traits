use super::FromUintUnchecked;
use crate::{ops::Shr1, CurveArithmetic, Scalar};
use ff::{Field, PrimeField};
use subtle::{ConstantTimeLess, CtOption};

/// Fast variable-time inversion using Stein's algorithm.
///
/// <https://link.springer.com/article/10.1007/s13389-016-0135-4>
#[allow(non_snake_case)]
pub fn invert_vartime<C>(scalar: &Scalar<C>) -> CtOption<Scalar<C>>
where
    C: CurveArithmetic,
    Scalar<C>: ConstantTimeLess + FromUintUnchecked<Uint = C::Uint> + Shr1,
{
    let order_div_2 = Scalar::<C>::from_uint_unchecked(C::ORDER >> 1);

    let mut u = *scalar;
    let mut v = Scalar::<C>::from_uint_unchecked(C::ORDER); // note: technically invalid
    let mut A = Scalar::<C>::ONE;
    let mut C = Scalar::<C>::ZERO;

    while !bool::from(u.is_zero()) {
        // u-loop
        while bool::from(u.is_even()) {
            u.shr1();

            let was_odd: bool = A.is_odd().into();
            A.shr1();

            if was_odd {
                A += order_div_2;
                A += Scalar::<C>::ONE;
            }
        }

        // v-loop
        while bool::from(v.is_even()) {
            v.shr1();

            let was_odd: bool = C.is_odd().into();
            C.shr1();

            if was_odd {
                C += order_div_2;
                C += Scalar::<C>::ONE;
            }
        }

        // sub-step
        if bool::from(u.ct_lt(&v)) {
            v -= &u;
            C -= &A;
        } else {
            u -= &v;
            A -= &C;
        }
    }

    CtOption::new(C, !scalar.is_zero())
}
