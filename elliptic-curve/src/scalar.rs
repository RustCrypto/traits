//! Scalar types.

#[cfg(feature = "arithmetic")]
pub(crate) mod non_zero;

use crate::{
    bigint::{AddMod, ArrayEncoding, Integer, Limb, NegMod, RandomMod, SubMod},
    rand_core::{CryptoRng, RngCore},
    subtle::{
        Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess,
        CtOption,
    },
    Curve, FieldBytes,
};
use core::{
    cmp::Ordering,
    ops::{Add, AddAssign, Neg, Sub, SubAssign},
};
use zeroize::DefaultIsZeroes;

#[cfg(feature = "arithmetic")]
use crate::{group::ff::PrimeField, ScalarArithmetic};

/// Scalar field element for a particular elliptic curve.
#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub type Scalar<C> = <C as ScalarArithmetic>::Scalar;

/// Bit representation of a scalar field element of a given curve.
#[cfg(feature = "bits")]
#[cfg_attr(docsrs, doc(cfg(feature = "bits")))]
pub type ScalarBits<C> = ff::FieldBits<<Scalar<C> as ff::PrimeFieldBits>::ReprBits>;

/// Generic core scalar type.
// TODO(tarcieri): make this a fully generic `Scalar` type
#[derive(Copy, Clone, Debug, Default)]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub struct ScalarCore<C: Curve> {
    /// Inner unsigned integer type.
    inner: C::UInt,
}

impl<C> ScalarCore<C>
where
    C: Curve,
{
    /// Zero scalar.
    pub const ZERO: Self = Self {
        inner: C::UInt::ZERO,
    };

    /// Multiplicative identity.
    pub const ONE: Self = Self {
        inner: C::UInt::ONE,
    };

    /// Scalar modulus.
    pub const MODULUS: C::UInt = C::ORDER;

    /// Generate a random [`ScalarCore`].
    pub fn random(rng: impl CryptoRng + RngCore) -> Self {
        Self {
            inner: C::UInt::random_mod(rng, &Self::MODULUS),
        }
    }

    /// Create a new scalar from [`Curve::UInt`].
    pub fn new(uint: C::UInt) -> CtOption<Self> {
        CtOption::new(Self { inner: uint }, uint.ct_lt(&Self::MODULUS))
    }

    /// Decode [`ScalarCore`] from big endian bytes.
    pub fn from_bytes_be(bytes: FieldBytes<C>) -> CtOption<Self> {
        Self::new(C::UInt::from_be_byte_array(bytes))
    }

    /// Decode [`ScalarCore`] from little endian bytes.
    pub fn from_bytes_le(bytes: FieldBytes<C>) -> CtOption<Self> {
        Self::new(C::UInt::from_le_byte_array(bytes))
    }

    /// Is this [`ScalarCore`] value equal to zero?
    pub fn is_zero(&self) -> Choice {
        self.inner.is_zero()
    }

    /// Encode [`ScalarCore`] as big endian bytes.
    pub fn to_bytes_be(self) -> FieldBytes<C> {
        self.inner.to_be_byte_array()
    }

    /// Encode [`ScalarCore`] as little endian bytes.
    pub fn to_bytes_le(self) -> FieldBytes<C> {
        self.inner.to_le_byte_array()
    }
}

#[cfg(feature = "arithmetic")]
impl<C> ScalarCore<C>
where
    C: Curve + ScalarArithmetic,
{
    /// Convert [`ScalarCore`] into a given curve's scalar type
    // TODO(tarcieri): replace curve-specific scalars with `ScalarCore`
    fn to_scalar(self) -> Scalar<C> {
        Scalar::<C>::from_repr(self.to_bytes_be()).unwrap()
    }
}

// TODO(tarcieri): better encapsulate this?
impl<C> AsRef<[Limb]> for ScalarCore<C>
where
    C: Curve,
{
    fn as_ref(&self) -> &[Limb] {
        self.inner.as_ref()
    }
}

impl<C> ConditionallySelectable for ScalarCore<C>
where
    C: Curve,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            inner: C::UInt::conditional_select(&a.inner, &b.inner, choice),
        }
    }
}

impl<C> ConstantTimeEq for ScalarCore<C>
where
    C: Curve,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.inner.ct_eq(&other.inner)
    }
}

impl<C> ConstantTimeLess for ScalarCore<C>
where
    C: Curve,
{
    fn ct_lt(&self, other: &Self) -> Choice {
        self.inner.ct_lt(&other.inner)
    }
}

impl<C> ConstantTimeGreater for ScalarCore<C>
where
    C: Curve,
{
    fn ct_gt(&self, other: &Self) -> Choice {
        self.inner.ct_gt(&other.inner)
    }
}

impl<C: Curve> DefaultIsZeroes for ScalarCore<C> {}

impl<C: Curve> Eq for ScalarCore<C> {}

impl<C> PartialEq for ScalarCore<C>
where
    C: Curve,
{
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<C> PartialOrd for ScalarCore<C>
where
    C: Curve,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.inner.cmp(&other.inner))
    }
}

impl<C> From<u64> for ScalarCore<C>
where
    C: Curve,
{
    fn from(n: u64) -> Self {
        Self {
            inner: C::UInt::from(n),
        }
    }
}

impl<C> Add<ScalarCore<C>> for ScalarCore<C>
where
    C: Curve,
{
    type Output = Self;

    fn add(self, other: Self) -> Self {
        self.add(&other)
    }
}

impl<C> Add<&ScalarCore<C>> for ScalarCore<C>
where
    C: Curve,
{
    type Output = Self;

    fn add(self, other: &Self) -> Self {
        Self {
            inner: self.inner.add_mod(&other.inner, &Self::MODULUS),
        }
    }
}

impl<C> AddAssign<ScalarCore<C>> for ScalarCore<C>
where
    C: Curve,
{
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl<C> AddAssign<&ScalarCore<C>> for ScalarCore<C>
where
    C: Curve,
{
    fn add_assign(&mut self, other: &Self) {
        *self = *self + other;
    }
}

impl<C> Sub<ScalarCore<C>> for ScalarCore<C>
where
    C: Curve,
{
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        self.sub(&other)
    }
}

impl<C> Sub<&ScalarCore<C>> for ScalarCore<C>
where
    C: Curve,
{
    type Output = Self;

    fn sub(self, other: &Self) -> Self {
        Self {
            inner: self.inner.sub_mod(&other.inner, &Self::MODULUS),
        }
    }
}

impl<C> SubAssign<ScalarCore<C>> for ScalarCore<C>
where
    C: Curve,
{
    fn sub_assign(&mut self, other: Self) {
        *self = *self - other;
    }
}

impl<C> SubAssign<&ScalarCore<C>> for ScalarCore<C>
where
    C: Curve,
{
    fn sub_assign(&mut self, other: &Self) {
        *self = *self - other;
    }
}

impl<C> Neg for ScalarCore<C>
where
    C: Curve,
{
    type Output = Self;

    fn neg(self) -> Self {
        Self {
            inner: self.inner.neg_mod(&Self::MODULUS),
        }
    }
}

impl<C> Neg for &ScalarCore<C>
where
    C: Curve,
{
    type Output = ScalarCore<C>;

    fn neg(self) -> ScalarCore<C> {
        -*self
    }
}
