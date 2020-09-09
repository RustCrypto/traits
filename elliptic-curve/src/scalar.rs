//! Scalar types

use crate::{
    ops::Invert,
    rand_core::{CryptoRng, RngCore},
    Arithmetic, Curve, FieldBytes, FromBytes,
};
use bitvec::{array::BitArray, order::Lsb0};
use core::ops::Deref;
use ff::Field;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Bit representation of a scalar field element of a given curve.
pub type ScalarBits<C> = BitArray<Lsb0, <<C as Arithmetic>::Scalar as ff::PrimeField>::ReprBits>;

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
    /// Generate a random `NonZeroScalar`
    pub fn random(mut rng: impl CryptoRng + RngCore) -> Self {
        // Use rejection sampling to eliminate zero values
        loop {
            let result = Self::new(C::Scalar::random(&mut rng));

            if result.is_some().into() {
                break result.unwrap();
            }
        }
    }

    /// Create a [`NonZeroScalar`] from a scalar, performing a constant-time
    /// check that it's non-zero.
    pub fn new(scalar: C::Scalar) -> CtOption<Self> {
        let zero = C::Scalar::from_bytes(&Default::default()).unwrap();
        let is_zero = scalar.ct_eq(&zero);
        CtOption::new(Self { scalar }, !is_zero)
    }

    /// Serialize this [`NonZeroScalar`] as a byte array
    pub fn to_bytes(&self) -> FieldBytes<C> {
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

impl<C> Deref for NonZeroScalar<C>
where
    C: Curve + Arithmetic,
{
    type Target = C::Scalar;

    fn deref(&self) -> &C::Scalar {
        &self.scalar
    }
}

impl<C> FromBytes for NonZeroScalar<C>
where
    C: Curve + Arithmetic,
{
    type Size = C::FieldSize;

    fn from_bytes(bytes: &FieldBytes<C>) -> CtOption<Self> {
        C::Scalar::from_bytes(bytes).and_then(Self::new)
    }
}

impl<C> From<NonZeroScalar<C>> for FieldBytes<C>
where
    C: Curve + Arithmetic,
{
    fn from(scalar: NonZeroScalar<C>) -> FieldBytes<C> {
        scalar.to_bytes()
    }
}

impl<C> Invert for NonZeroScalar<C>
where
    C: Curve + Arithmetic,
    C::Scalar: Invert,
{
    type Output = C::Scalar;

    /// Perform a scalar inversion
    fn invert(&self) -> CtOption<Self::Output> {
        ff::Field::invert(&self.scalar)
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
