//! Non-zero scalar type.
// TODO(tarcieri): change bounds to `ScalarArithmetic` instead of `ProjectiveArithmetic`

use crate::{
    bigint::Encoding as _,
    ops::Invert,
    rand_core::{CryptoRng, RngCore},
    Curve, Error, FieldBytes, ProjectiveArithmetic, Result, Scalar, ScalarCore, SecretKey,
};
use core::{convert::TryFrom, ops::Deref};
use ff::{Field, PrimeField};
use generic_array::GenericArray;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::Zeroize;

/// Non-zero scalar type.
///
/// This type ensures that its value is not zero, ala `core::num::NonZero*`.
/// To do this, the generic `S` type must impl both `Default` and
/// `ConstantTimeEq`, with the requirement that `S::default()` returns 0.
///
/// In the context of ECC, it's useful for ensuring that scalar multiplication
/// cannot result in the point at infinity.
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
#[derive(Clone)]
pub struct NonZeroScalar<C>
where
    C: Curve + ProjectiveArithmetic,
{
    scalar: Scalar<C>,
}

impl<C> NonZeroScalar<C>
where
    C: Curve + ProjectiveArithmetic,
{
    /// Generate a random `NonZeroScalar`.
    pub fn random(mut rng: impl CryptoRng + RngCore) -> Self {
        // Use rejection sampling to eliminate zero values.
        // While this method isn't constant-time, the attacker shouldn't learn
        // anything about unrelated outputs so long as `rng` is a secure `CryptoRng`.
        loop {
            if let Some(result) = Self::new(Field::random(&mut rng)).into() {
                break result;
            }
        }
    }

    /// Create a [`NonZeroScalar`] from a scalar.
    pub fn new(scalar: Scalar<C>) -> CtOption<Self> {
        CtOption::new(Self { scalar }, !scalar.is_zero())
    }

    /// Decode a [`NonZeroScalar`] from a big endian-serialized field element.
    pub fn from_repr(repr: FieldBytes<C>) -> CtOption<Self> {
        Scalar::<C>::from_repr(repr).and_then(Self::new)
    }
}

impl<C> AsRef<Scalar<C>> for NonZeroScalar<C>
where
    C: Curve + ProjectiveArithmetic,
{
    fn as_ref(&self) -> &Scalar<C> {
        &self.scalar
    }
}

impl<C> ConditionallySelectable for NonZeroScalar<C>
where
    C: Curve + ProjectiveArithmetic,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            scalar: Scalar::<C>::conditional_select(&a.scalar, &b.scalar, choice),
        }
    }
}

impl<C> ConstantTimeEq for NonZeroScalar<C>
where
    C: Curve + ProjectiveArithmetic,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.scalar.ct_eq(&other.scalar)
    }
}

impl<C> Copy for NonZeroScalar<C> where C: Curve + ProjectiveArithmetic {}

impl<C> Deref for NonZeroScalar<C>
where
    C: Curve + ProjectiveArithmetic,
{
    type Target = Scalar<C>;

    fn deref(&self) -> &Scalar<C> {
        &self.scalar
    }
}

impl<C> From<NonZeroScalar<C>> for FieldBytes<C>
where
    C: Curve + ProjectiveArithmetic,
{
    fn from(scalar: NonZeroScalar<C>) -> FieldBytes<C> {
        Self::from(&scalar)
    }
}

impl<C> From<&NonZeroScalar<C>> for FieldBytes<C>
where
    C: Curve + ProjectiveArithmetic,
{
    fn from(scalar: &NonZeroScalar<C>) -> FieldBytes<C> {
        scalar.to_repr()
    }
}

impl<C> From<NonZeroScalar<C>> for ScalarCore<C>
where
    C: Curve + ProjectiveArithmetic,
{
    fn from(scalar: NonZeroScalar<C>) -> ScalarCore<C> {
        ScalarCore::from_be_bytes(scalar.to_repr()).unwrap()
    }
}

impl<C> From<&NonZeroScalar<C>> for ScalarCore<C>
where
    C: Curve + ProjectiveArithmetic,
{
    fn from(scalar: &NonZeroScalar<C>) -> ScalarCore<C> {
        ScalarCore::from_be_bytes(scalar.to_repr()).unwrap()
    }
}

impl<C> From<SecretKey<C>> for NonZeroScalar<C>
where
    C: Curve + ProjectiveArithmetic,
{
    fn from(sk: SecretKey<C>) -> NonZeroScalar<C> {
        Self::from(&sk)
    }
}

impl<C> From<&SecretKey<C>> for NonZeroScalar<C>
where
    C: Curve + ProjectiveArithmetic,
{
    fn from(sk: &SecretKey<C>) -> NonZeroScalar<C> {
        let scalar = sk.as_scalar_core().to_scalar();
        debug_assert!(!bool::from(scalar.is_zero()));
        Self { scalar }
    }
}

impl<C> Invert for NonZeroScalar<C>
where
    C: Curve + ProjectiveArithmetic,
{
    type Output = Scalar<C>;

    /// Perform a scalar inversion
    fn invert(&self) -> CtOption<Self::Output> {
        ff::Field::invert(&self.scalar)
    }
}

impl<C> TryFrom<&[u8]> for NonZeroScalar<C>
where
    C: Curve + ProjectiveArithmetic,
{
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        if bytes.len() == C::UInt::BYTE_SIZE {
            Option::from(NonZeroScalar::from_repr(GenericArray::clone_from_slice(
                bytes,
            )))
            .ok_or(Error)
        } else {
            Err(Error)
        }
    }
}

impl<C> Zeroize for NonZeroScalar<C>
where
    C: Curve + ProjectiveArithmetic,
{
    fn zeroize(&mut self) {
        self.scalar.zeroize();
    }
}

#[cfg(all(test, feature = "dev"))]
mod tests {
    use crate::dev::NonZeroScalar;
    use ff::PrimeField;
    use hex_literal::hex;

    #[test]
    fn round_trip() {
        let bytes = hex!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let scalar = NonZeroScalar::from_repr(bytes.into()).unwrap();
        assert_eq!(&bytes, scalar.to_repr().as_slice());
    }
}
