//! Development-related functionality: helpers and types for writing tests
//! against concrete implementations of the traits in this crate.

use crate::{
    bigint::{ArrayEncoding as _, U256},
    error::{Error, Result},
    rand_core::RngCore,
    sec1::{FromEncodedPoint, ToEncodedPoint},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    weierstrass,
    zeroize::Zeroize,
    AffineArithmetic, AlgorithmParameters, Curve, ProjectiveArithmetic, ScalarArithmetic,
};
use core::{
    convert::{TryFrom, TryInto},
    iter::Sum,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use ff::{Field, PrimeField};
use hex_literal::hex;

#[cfg(feature = "bits")]
use crate::{group::ff::PrimeFieldBits, ScalarBits};

#[cfg(feature = "jwk")]
use crate::JwkParameters;

/// Pseudo-coordinate for fixed-based scalar mult output
pub const PSEUDO_COORDINATE_FIXED_BASE_MUL: [u8; 32] =
    hex!("deadbeef00000000000000000000000000000000000000000000000000000001");

/// Mock elliptic curve type useful for writing tests which require a concrete
/// curve type.
///
/// Note: this type is roughly modeled off of NIST P-256, but does not provide
/// an actual cure arithmetic implementation.
#[derive(Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct MockCurve;

impl Curve for MockCurve {
    type UInt = U256;

    const ORDER: U256 =
        U256::from_be_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
}

impl weierstrass::Curve for MockCurve {}

impl AffineArithmetic for MockCurve {
    type AffinePoint = AffinePoint;
}

impl ProjectiveArithmetic for MockCurve {
    type ProjectivePoint = ProjectivePoint;
}

impl ScalarArithmetic for MockCurve {
    type Scalar = Scalar;
}

impl AlgorithmParameters for MockCurve {
    /// OID for NIST P-256
    const OID: pkcs8::ObjectIdentifier = pkcs8::ObjectIdentifier::new("1.2.840.10045.3.1.7");
}

#[cfg(feature = "jwk")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwk")))]
impl JwkParameters for MockCurve {
    const CRV: &'static str = "P-256";
}

/// SEC1 encoded point.
pub type EncodedPoint = crate::sec1::EncodedPoint<MockCurve>;

/// Field element bytes.
pub type FieldBytes = crate::FieldBytes<MockCurve>;

/// Non-zero scalar value.
pub type NonZeroScalar = crate::NonZeroScalar<MockCurve>;

/// Public key.
pub type PublicKey = crate::PublicKey<MockCurve>;

/// Secret key.
pub type SecretKey = crate::SecretKey<MockCurve>;

/// Scalar bytes.
pub type ScalarBytes = crate::ScalarBytes<MockCurve>;

/// Example scalar type
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Scalar(U256);

impl Field for Scalar {
    fn random(_rng: impl RngCore) -> Self {
        unimplemented!();
    }

    fn zero() -> Self {
        Self(U256::ZERO)
    }

    fn one() -> Self {
        Self(U256::ONE)
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero().into()
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

    const NUM_BITS: u32 = 256;
    const CAPACITY: u32 = 255;
    const S: u32 = 4;

    fn from_repr(bytes: FieldBytes) -> Option<Self> {
        U256::from_be_byte_array(bytes).try_into().ok()
    }

    fn to_repr(&self) -> FieldBytes {
        self.0.to_be_byte_array()
    }

    fn is_odd(&self) -> bool {
        unimplemented!();
    }

    fn multiplicative_generator() -> Self {
        unimplemented!();
    }

    fn root_of_unity() -> Self {
        unimplemented!();
    }
}

#[cfg(feature = "bits")]
impl PrimeFieldBits for Scalar {
    #[cfg(target_pointer_width = "32")]
    type ReprBits = [u32; 8];
    #[cfg(target_pointer_width = "64")]
    type ReprBits = [u64; 4];

    fn to_le_bits(&self) -> ScalarBits<MockCurve> {
        let mut limbs = Self::ReprBits::default();

        for (i, limb) in self.0.limbs().iter().cloned().enumerate() {
            limbs[i] = limb.into();
        }

        limbs.into()
    }

    fn char_le_bits() -> ScalarBits<MockCurve> {
        let mut limbs = Self::ReprBits::default();

        for (i, limb) in MockCurve::ORDER.limbs().iter().cloned().enumerate() {
            limbs[i] = limb.into();
        }

        limbs.into()
    }
}

impl TryFrom<U256> for Scalar {
    type Error = Error;

    fn try_from(w: U256) -> Result<Self> {
        if w < MockCurve::ORDER {
            Ok(Scalar(w))
        } else {
            Err(Error)
        }
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Scalar(U256::conditional_select(&a.0, &b.0, choice))
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
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
        scalar.to_repr()
    }
}

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.0.as_mut().zeroize();
    }
}

/// Example affine point type
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AffinePoint {
    /// Result of fixed-based scalar multiplication
    FixedBaseOutput(Scalar),

    /// Is this point the identity point?
    Identity,

    /// Is this point the generator point?
    Generator,

    /// Is this point a different point corresponding to a given [`EncodedPoint`]
    Other(EncodedPoint),
}

impl ConstantTimeEq for AffinePoint {
    fn ct_eq(&self, _other: &Self) -> Choice {
        unimplemented!();
    }
}

impl ConditionallySelectable for AffinePoint {
    fn conditional_select(_a: &Self, _b: &Self, _choice: Choice) -> Self {
        unimplemented!();
    }
}

impl Default for AffinePoint {
    fn default() -> Self {
        Self::Identity
    }
}

impl FromEncodedPoint<MockCurve> for AffinePoint {
    fn from_encoded_point(point: &EncodedPoint) -> Option<Self> {
        if point.is_identity() {
            Some(Self::Identity)
        } else {
            Some(Self::Other(*point))
        }
    }
}

impl ToEncodedPoint<MockCurve> for AffinePoint {
    fn to_encoded_point(&self, compress: bool) -> EncodedPoint {
        match self {
            Self::FixedBaseOutput(scalar) => EncodedPoint::from_affine_coordinates(
                &scalar.to_repr(),
                &PSEUDO_COORDINATE_FIXED_BASE_MUL.into(),
                false,
            ),
            Self::Other(point) => {
                if compress == point.is_compressed() {
                    *point
                } else {
                    unimplemented!();
                }
            }
            _ => unimplemented!(),
        }
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
pub enum ProjectivePoint {
    /// Result of fixed-based scalar multiplication
    FixedBaseOutput(Scalar),

    /// Is this point the identity point?
    Identity,

    /// Is this point the generator point?
    Generator,

    /// Is this point a different point corresponding to a given [`AffinePoint`]
    Other(AffinePoint),
}

impl ConstantTimeEq for ProjectivePoint {
    fn ct_eq(&self, _other: &Self) -> Choice {
        unimplemented!();
    }
}

impl ConditionallySelectable for ProjectivePoint {
    fn conditional_select(_a: &Self, _b: &Self, _choice: Choice) -> Self {
        unimplemented!();
    }
}

impl Default for ProjectivePoint {
    fn default() -> Self {
        Self::Identity
    }
}

impl From<AffinePoint> for ProjectivePoint {
    fn from(point: AffinePoint) -> ProjectivePoint {
        match point {
            AffinePoint::FixedBaseOutput(scalar) => ProjectivePoint::FixedBaseOutput(scalar),
            AffinePoint::Identity => ProjectivePoint::Identity,
            AffinePoint::Generator => ProjectivePoint::Generator,
            other => ProjectivePoint::Other(other),
        }
    }
}

impl From<ProjectivePoint> for AffinePoint {
    fn from(point: ProjectivePoint) -> AffinePoint {
        group::Curve::to_affine(&point)
    }
}

impl FromEncodedPoint<MockCurve> for ProjectivePoint {
    fn from_encoded_point(_point: &EncodedPoint) -> Option<Self> {
        unimplemented!();
    }
}

impl ToEncodedPoint<MockCurve> for ProjectivePoint {
    fn to_encoded_point(&self, _compress: bool) -> EncodedPoint {
        unimplemented!();
    }
}

impl group::Group for ProjectivePoint {
    type Scalar = Scalar;

    fn random(_rng: impl RngCore) -> Self {
        unimplemented!();
    }

    fn identity() -> Self {
        Self::Identity
    }

    fn generator() -> Self {
        Self::Generator
    }

    fn is_identity(&self) -> Choice {
        Choice::from((self == &Self::Identity) as u8)
    }

    #[must_use]
    fn double(&self) -> Self {
        unimplemented!();
    }
}

impl group::Curve for ProjectivePoint {
    type AffineRepr = AffinePoint;

    fn to_affine(&self) -> AffinePoint {
        match self {
            Self::FixedBaseOutput(scalar) => AffinePoint::FixedBaseOutput(*scalar),
            Self::Other(affine) => *affine,
            _ => unimplemented!(),
        }
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

    fn mul(self, scalar: Scalar) -> ProjectivePoint {
        match self {
            Self::Generator => Self::FixedBaseOutput(scalar),
            _ => unimplemented!(),
        }
    }
}

impl Mul<&Scalar> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn mul(self, scalar: &Scalar) -> ProjectivePoint {
        self * *scalar
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
