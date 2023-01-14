//! Scalar types.

use subtle::Choice;

pub(crate) mod core;

#[cfg(feature = "arithmetic")]
pub(crate) mod nonzero;

#[cfg(feature = "arithmetic")]
use crate::CurveArithmetic;

/// Scalar field element for a particular elliptic curve.
#[cfg(feature = "arithmetic")]
pub type Scalar<C> = <C as CurveArithmetic>::Scalar;

/// Bit representation of a scalar field element of a given curve.
#[cfg(feature = "bits")]
pub type ScalarBits<C> = ff::FieldBits<<Scalar<C> as ff::PrimeFieldBits>::ReprBits>;

/// Is this scalar greater than n / 2?
///
/// # Returns
///
/// - For scalars 0 through n / 2: `Choice::from(0)`
/// - For scalars (n / 2) + 1 through n - 1: `Choice::from(1)`
pub trait IsHigh {
    /// Is this scalar greater than or equal to n / 2?
    fn is_high(&self) -> Choice;
}
