//! Scalar types

use crate::{Arithmetic, Curve};
use subtle::{ConstantTimeEq, CtOption};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Non-zero scalar type.
///
/// This type ensures that its value is not zero, ala `core::num::NonZero*`.
/// To do this, the generic `S` type must impl both `Default` and
/// `ConstantTimeEq`, with the requirement that `S::default()` returns 0.
///
/// In the context of ECC, it's useful for ensuring that scalar multiplication
/// cannot result in the point at infinity.
pub struct NonZeroScalar<C: Curve + Arithmetic> {
    scalar: C::Scalar,
}

impl<C> NonZeroScalar<C>
where
    C: Curve + Arithmetic,
{
    /// Create a [`NonZeroScalar`] from a scalar, performing a constant-time
    /// check that it's non-zero.
    pub fn new(scalar: C::Scalar) -> CtOption<Self> {
        let is_zero = scalar.ct_eq(&C::Scalar::default());
        CtOption::new(Self { scalar }, !is_zero)
    }
}

impl<C> AsRef<C::Scalar> for NonZeroScalar<C>
where
    C: Curve + Arithmetic,
{
    fn as_ref(&self) -> &C::Scalar {
        &self.scalar
    }
}

#[cfg(feature = "zeroize")]
impl<C> Zeroize for NonZeroScalar<C>
where
    C: Curve + Arithmetic,
    C::Scalar: Zeroize,
{
    fn zeroize(&mut self) {
        self.scalar.zeroize();
    }
}
