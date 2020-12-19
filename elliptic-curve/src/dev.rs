//! Development-related functionality: helpers and types for writing tests
//! against concrete implementations of the traits in this crate.

use crate::{
    consts::U32,
    digest::Digest,
    ff::{Field, PrimeField},
    group,
    rand_core::RngCore,
    scalar::ScalarBits,
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    util::{adc64, sbb64},
    weierstrass,
    zeroize::Zeroize,
    Curve, FromDigest, ProjectiveArithmetic,
};
use core::{
    convert::TryInto,
    iter::Sum,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

/// Mock elliptic curve type useful for writing tests which require a concrete
/// curve type.
///
/// Note: this type is roughly modeled off of NIST P-256, but does not provide
/// an actual cure arithmetic implementation.
#[derive(Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct MockCurve;

impl Curve for MockCurve {
    type FieldSize = U32;
}

impl weierstrass::Curve for MockCurve {}

impl ProjectiveArithmetic for MockCurve {
    type ProjectivePoint = ProjectivePoint;
}

/// Field element bytes.
pub type FieldBytes = crate::FieldBytes<MockCurve>;

/// Non-zero scalar value.
pub type NonZeroScalar = crate::scalar::NonZeroScalar<MockCurve>;

const LIMBS: usize = 4;

type U256 = [u64; LIMBS];

// Note: P-256 modulus
const MODULUS: U256 = [
    0xf3b9_cac2_fc63_2551,
    0xbce6_faad_a717_9e84,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_0000_0000,
];

/// Example scalar type
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Scalar([u64; LIMBS]);

impl Field for Scalar {
    fn random(_rng: impl RngCore) -> Self {
        unimplemented!();
    }

    fn zero() -> Self {
        Self(Default::default())
    }

    fn one() -> Self {
        unimplemented!();
    }

    fn is_zero(&self) -> bool {
        self.ct_eq(&Self::zero()).into()
    }

    #[must_use]
    fn square(&self) -> Self {
        unimplemented!();
    }

    #[must_use]
    fn double(&self) -> Self {
        unimplemented!();
    }

    fn invert(&self) -> CtOption<Self> {
        unimplemented!();
    }

    fn sqrt(&self) -> CtOption<Self> {
        unimplemented!();
    }
}

impl PrimeField for Scalar {
    type Repr = FieldBytes;

    #[cfg(target_pointer_width = "32")]
    type ReprBits = [u32; 8];

    #[cfg(target_pointer_width = "64")]
    type ReprBits = [u64; 4];

    const NUM_BITS: u32 = 256;
    const CAPACITY: u32 = 255;
    const S: u32 = 4;

    fn from_repr(bytes: FieldBytes) -> Option<Self> {
        let mut w = [0u64; LIMBS];

        // Interpret the bytes as a big-endian integer w.
        w[3] = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
        w[2] = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
        w[1] = u64::from_be_bytes(bytes[16..24].try_into().unwrap());
        w[0] = u64::from_be_bytes(bytes[24..32].try_into().unwrap());

        // If w is in the range [0, n) then w - n will overflow, resulting in a borrow
        // value of 2^64 - 1.
        let (_, borrow) = sbb64(w[0], MODULUS[0], 0);
        let (_, borrow) = sbb64(w[1], MODULUS[1], borrow);
        let (_, borrow) = sbb64(w[2], MODULUS[2], borrow);
        let (_, borrow) = sbb64(w[3], MODULUS[3], borrow);

        if (borrow as u8) & 1 == 1 {
            Some(Scalar(w))
        } else {
            None
        }
    }

    fn to_repr(&self) -> FieldBytes {
        let mut ret = FieldBytes::default();
        ret[0..8].copy_from_slice(&self.0[3].to_be_bytes());
        ret[8..16].copy_from_slice(&self.0[2].to_be_bytes());
        ret[16..24].copy_from_slice(&self.0[1].to_be_bytes());
        ret[24..32].copy_from_slice(&self.0[0].to_be_bytes());
        ret
    }

    fn to_le_bits(&self) -> ScalarBits<MockCurve> {
        unimplemented!();
    }

    fn is_odd(&self) -> bool {
        unimplemented!();
    }

    fn char_le_bits() -> ScalarBits<MockCurve> {
        unimplemented!();
    }

    fn multiplicative_generator() -> Self {
        unimplemented!();
    }

    fn root_of_unity() -> Self {
        unimplemented!();
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Scalar([
            u64::conditional_select(&a.0[0], &b.0[0], choice),
            u64::conditional_select(&a.0[1], &b.0[1], choice),
            u64::conditional_select(&a.0[2], &b.0[2], choice),
            u64::conditional_select(&a.0[3], &b.0[3], choice),
        ])
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0[0].ct_eq(&other.0[0])
            & self.0[1].ct_eq(&other.0[1])
            & self.0[2].ct_eq(&other.0[2])
            & self.0[3].ct_eq(&other.0[3])
    }
}

impl Add<Scalar> for Scalar {
    type Output = Scalar;

    fn add(self, _other: Scalar) -> Scalar {
        unimplemented!();
    }
}

impl Add<&Scalar> for Scalar {
    type Output = Scalar;

    fn add(self, _other: &Scalar) -> Scalar {
        unimplemented!();
    }
}

impl AddAssign<Scalar> for Scalar {
    fn add_assign(&mut self, _rhs: Scalar) {
        unimplemented!();
    }
}

impl AddAssign<&Scalar> for Scalar {
    fn add_assign(&mut self, _rhs: &Scalar) {
        unimplemented!();
    }
}

impl Sub<Scalar> for Scalar {
    type Output = Scalar;

    fn sub(self, _other: Scalar) -> Scalar {
        unimplemented!();
    }
}

impl Sub<&Scalar> for Scalar {
    type Output = Scalar;

    fn sub(self, _other: &Scalar) -> Scalar {
        unimplemented!();
    }
}

impl SubAssign<Scalar> for Scalar {
    fn sub_assign(&mut self, _rhs: Scalar) {
        unimplemented!();
    }
}

impl SubAssign<&Scalar> for Scalar {
    fn sub_assign(&mut self, _rhs: &Scalar) {
        unimplemented!();
    }
}

impl Mul<Scalar> for Scalar {
    type Output = Scalar;

    fn mul(self, _other: Scalar) -> Scalar {
        unimplemented!();
    }
}

impl Mul<&Scalar> for Scalar {
    type Output = Scalar;

    fn mul(self, _other: &Scalar) -> Scalar {
        unimplemented!();
    }
}

impl MulAssign<Scalar> for Scalar {
    fn mul_assign(&mut self, _rhs: Scalar) {
        unimplemented!();
    }
}

impl MulAssign<&Scalar> for Scalar {
    fn mul_assign(&mut self, _rhs: &Scalar) {
        unimplemented!();
    }
}

impl Neg for Scalar {
    type Output = Scalar;

    fn neg(self) -> Scalar {
        unimplemented!();
    }
}

impl From<u64> for Scalar {
    fn from(_: u64) -> Scalar {
        unimplemented!();
    }
}

impl From<Scalar> for FieldBytes {
    fn from(scalar: Scalar) -> Self {
        Self::from(&scalar)
    }
}

impl From<&Scalar> for FieldBytes {
    fn from(scalar: &Scalar) -> Self {
        let mut ret = FieldBytes::default();
        ret[0..8].copy_from_slice(&scalar.0[3].to_be_bytes());
        ret[8..16].copy_from_slice(&scalar.0[2].to_be_bytes());
        ret[16..24].copy_from_slice(&scalar.0[1].to_be_bytes());
        ret[24..32].copy_from_slice(&scalar.0[0].to_be_bytes());
        ret
    }
}

impl FromDigest<MockCurve> for Scalar {
    fn from_digest<D>(digest: D) -> Self
    where
        D: Digest<OutputSize = U32>,
    {
        let bytes = digest.finalize();

        Self::sub_inner(
            u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
            u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
            u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
            u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
            0,
            MODULUS[0],
            MODULUS[1],
            MODULUS[2],
            MODULUS[3],
            0,
        )
    }
}

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.0.as_mut().zeroize()
    }
}

impl Scalar {
    #[allow(clippy::too_many_arguments)]
    const fn sub_inner(
        l0: u64,
        l1: u64,
        l2: u64,
        l3: u64,
        l4: u64,
        r0: u64,
        r1: u64,
        r2: u64,
        r3: u64,
        r4: u64,
    ) -> Self {
        let (w0, borrow) = sbb64(l0, r0, 0);
        let (w1, borrow) = sbb64(l1, r1, borrow);
        let (w2, borrow) = sbb64(l2, r2, borrow);
        let (w3, borrow) = sbb64(l3, r3, borrow);
        let (_, borrow) = sbb64(l4, r4, borrow);

        let (w0, carry) = adc64(w0, MODULUS[0] & borrow, 0);
        let (w1, carry) = adc64(w1, MODULUS[1] & borrow, carry);
        let (w2, carry) = adc64(w2, MODULUS[2] & borrow, carry);
        let (w3, _) = adc64(w3, MODULUS[3] & borrow, carry);

        Scalar([w0, w1, w2, w3])
    }
}

/// Example affine point type
#[derive(Clone, Copy, Debug)]
pub struct AffinePoint {}

impl ConditionallySelectable for AffinePoint {
    fn conditional_select(_a: &Self, _b: &Self, _choice: Choice) -> Self {
        unimplemented!();
    }
}

impl Mul<NonZeroScalar> for AffinePoint {
    type Output = AffinePoint;

    fn mul(self, _scalar: NonZeroScalar) -> Self {
        unimplemented!();
    }
}

/// Example projective point type
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectivePoint {}

impl group::Group for ProjectivePoint {
    type Scalar = Scalar;

    fn random(_rng: impl RngCore) -> Self {
        unimplemented!();
    }

    fn identity() -> Self {
        unimplemented!();
    }

    fn generator() -> Self {
        unimplemented!();
    }

    fn is_identity(&self) -> Choice {
        unimplemented!();
    }

    #[must_use]
    fn double(&self) -> Self {
        unimplemented!();
    }
}

impl group::Curve for ProjectivePoint {
    type AffineRepr = AffinePoint;

    fn to_affine(&self) -> AffinePoint {
        unimplemented!();
    }
}

impl Add<ProjectivePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn add(self, _other: ProjectivePoint) -> ProjectivePoint {
        unimplemented!();
    }
}

impl Add<&ProjectivePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn add(self, _other: &ProjectivePoint) -> ProjectivePoint {
        unimplemented!();
    }
}

impl AddAssign<ProjectivePoint> for ProjectivePoint {
    fn add_assign(&mut self, _rhs: ProjectivePoint) {
        unimplemented!();
    }
}

impl AddAssign<&ProjectivePoint> for ProjectivePoint {
    fn add_assign(&mut self, _rhs: &ProjectivePoint) {
        unimplemented!();
    }
}

impl Sub<ProjectivePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn sub(self, _other: ProjectivePoint) -> ProjectivePoint {
        unimplemented!();
    }
}

impl Sub<&ProjectivePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn sub(self, _other: &ProjectivePoint) -> ProjectivePoint {
        unimplemented!();
    }
}

impl SubAssign<ProjectivePoint> for ProjectivePoint {
    fn sub_assign(&mut self, _rhs: ProjectivePoint) {
        unimplemented!();
    }
}

impl SubAssign<&ProjectivePoint> for ProjectivePoint {
    fn sub_assign(&mut self, _rhs: &ProjectivePoint) {
        unimplemented!();
    }
}

impl Add<AffinePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn add(self, _other: AffinePoint) -> ProjectivePoint {
        unimplemented!();
    }
}

impl Add<&AffinePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn add(self, _other: &AffinePoint) -> ProjectivePoint {
        unimplemented!();
    }
}

impl AddAssign<AffinePoint> for ProjectivePoint {
    fn add_assign(&mut self, _rhs: AffinePoint) {
        unimplemented!();
    }
}

impl AddAssign<&AffinePoint> for ProjectivePoint {
    fn add_assign(&mut self, _rhs: &AffinePoint) {
        unimplemented!();
    }
}

impl Sum for ProjectivePoint {
    fn sum<I: Iterator<Item = Self>>(_iter: I) -> Self {
        unimplemented!();
    }
}

impl<'a> Sum<&'a ProjectivePoint> for ProjectivePoint {
    fn sum<I: Iterator<Item = &'a ProjectivePoint>>(_iter: I) -> Self {
        unimplemented!();
    }
}

impl Sub<AffinePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn sub(self, _other: AffinePoint) -> ProjectivePoint {
        unimplemented!();
    }
}

impl Sub<&AffinePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn sub(self, _other: &AffinePoint) -> ProjectivePoint {
        unimplemented!();
    }
}

impl SubAssign<AffinePoint> for ProjectivePoint {
    fn sub_assign(&mut self, _rhs: AffinePoint) {
        unimplemented!();
    }
}

impl SubAssign<&AffinePoint> for ProjectivePoint {
    fn sub_assign(&mut self, _rhs: &AffinePoint) {
        unimplemented!();
    }
}

impl Mul<Scalar> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn mul(self, _other: Scalar) -> ProjectivePoint {
        unimplemented!();
    }
}

impl Mul<&Scalar> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn mul(self, _other: &Scalar) -> ProjectivePoint {
        unimplemented!();
    }
}

impl MulAssign<Scalar> for ProjectivePoint {
    fn mul_assign(&mut self, _rhs: Scalar) {
        unimplemented!();
    }
}

impl MulAssign<&Scalar> for ProjectivePoint {
    fn mul_assign(&mut self, _rhs: &Scalar) {
        unimplemented!();
    }
}

impl Neg for ProjectivePoint {
    type Output = ProjectivePoint;

    fn neg(self) -> ProjectivePoint {
        unimplemented!();
    }
}
