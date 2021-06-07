//! Scalar types.

pub(crate) mod bytes;

#[cfg(feature = "arithmetic")]
use crate::ScalarArithmetic;

#[cfg(feature = "arithmetic")]
pub(crate) mod non_zero;

/// Scalar field element for a particular elliptic curve.
#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub type Scalar<C> = <C as ScalarArithmetic>::Scalar;

/// Bit representation of a scalar field element of a given curve.
#[cfg(feature = "bits")]
#[cfg_attr(docsrs, doc(cfg(feature = "bits")))]
pub type ScalarBits<C> = ff::FieldBits<<Scalar<C> as ff::PrimeFieldBits>::ReprBits>;
