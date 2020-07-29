//! Elliptic curves in short Weierstrass form.

pub mod point;
pub mod public_key;

pub use self::{
    point::{CompressedPoint, CompressedPointSize, UncompressedPoint, UncompressedPointSize},
    public_key::{FromPublicKey, PublicKey},
};

use crate::{Arithmetic, ScalarBytes};
use subtle::CtOption;

/// Marker trait for elliptic curves in short Weierstrass form
pub trait Curve: super::Curve {}

/// Fixed-base scalar multiplication
pub trait FixedBaseScalarMul: Curve + Arithmetic {
    /// Multiply the given scalar by the generator point for this elliptic
    /// curve.
    // TODO(tarcieri): use `Self::Scalar` for the `scalar` param
    fn mul_base(scalar: &ScalarBytes<Self>) -> CtOption<Self::AffinePoint>;
}
