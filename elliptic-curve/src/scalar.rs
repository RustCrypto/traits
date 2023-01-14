//! Scalar types.

mod core;
#[cfg(feature = "arithmetic")]
mod invert;
#[cfg(feature = "arithmetic")]
mod nonzero;

pub use self::core::ScalarCore;
#[cfg(feature = "arithmetic")]
pub use self::{invert::invert_vartime, nonzero::NonZeroScalar};

use subtle::Choice;

#[cfg(feature = "arithmetic")]
use crate::{bigint::Integer, CurveArithmetic};

/// Scalar field element for a particular elliptic curve.
#[cfg(feature = "arithmetic")]
pub type Scalar<C> = <C as CurveArithmetic>::Scalar;

/// Bit representation of a scalar field element of a given curve.
#[cfg(feature = "bits")]
pub type ScalarBits<C> = ff::FieldBits<<Scalar<C> as ff::PrimeFieldBits>::ReprBits>;

/// Instantiate a scalar from an unsigned integer without checking for overflow.
#[cfg(feature = "arithmetic")]
pub trait FromUintUnchecked: ff::Field {
    /// Unsigned integer type (i.e. `Curve::Uint`)
    type Uint: Integer;

    /// Instantiate scalar from an unsigned integer without checking
    /// whether the value overflows the field modulus.
    ///
    /// Incorrectly used this can lead to mathematically invalid results.
    /// Use with care!
    fn from_uint_unchecked(uint: Self::Uint) -> Self;
}

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
