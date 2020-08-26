//! Scalar types

use crate::{ops::Invert, Arithmetic, Curve, ElementBytes, FromBytes};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

#[cfg(feature = "rand")]
use crate::{
    rand_core::{CryptoRng, RngCore},
    Generate,
};

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
#[derive(Clone)]
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
        let zero = C::Scalar::from_bytes(&Default::default()).unwrap();
        let is_zero = scalar.ct_eq(&zero);
        CtOption::new(Self { scalar }, !is_zero)
    }

    /// Serialize this [`NonZeroScalar`] as a byte array
    pub fn to_bytes(&self) -> ElementBytes<C> {
        self.scalar.into()
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

impl<C> ConditionallySelectable for NonZeroScalar<C>
where
    C: Curve + Arithmetic,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let scalar = C::Scalar::conditional_select(&a.scalar, &b.scalar, choice);
        Self { scalar }
    }
}

impl<C> Copy for NonZeroScalar<C> where C: Curve + Arithmetic {}

impl<C> FromBytes for NonZeroScalar<C>
where
    C: Curve + Arithmetic,
{
    type Size = C::ElementSize;

    fn from_bytes(bytes: &ElementBytes<C>) -> CtOption<Self> {
        C::Scalar::from_bytes(bytes).and_then(Self::new)
    }
}

impl<C> From<NonZeroScalar<C>> for ElementBytes<C>
where
    C: Curve + Arithmetic,
{
    fn from(scalar: NonZeroScalar<C>) -> ElementBytes<C> {
        scalar.to_bytes()
    }
}

impl<C> Invert for NonZeroScalar<C>
where
    C: Curve + Arithmetic,
    C::Scalar: Invert,
{
    type Output = <C::Scalar as Invert>::Output;

    /// Perform a scalar inversion
    fn invert(&self) -> CtOption<Self::Output> {
        self.scalar.invert()
    }
}

#[cfg(feature = "rand")]
impl<C> Generate for NonZeroScalar<C>
where
    C: Curve + Arithmetic,
    C::Scalar: Generate,
{
    fn generate(mut rng: impl CryptoRng + RngCore) -> Self {
        // Use rejection sampling to eliminate zero values
        loop {
            let result = Self::new(C::Scalar::generate(&mut rng));

            if result.is_some().into() {
                break result.unwrap();
            }
        }
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
