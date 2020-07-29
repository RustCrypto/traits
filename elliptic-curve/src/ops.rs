//! Traits for arithmetic operations on elliptic curve field elements

use subtle::CtOption;

/// Perform an inversion on a field element (i.e. base field element or scalar)
pub trait Invert {
    /// Field element type
    type Output;

    /// Invert a field element.
    fn invert(&self) -> CtOption<Self::Output>;
}

/// Fixed-base scalar multiplication
pub trait MulBase {
    /// Affine point type
    type Output;

    /// Multiply this value by the generator point for the elliptic curve
    fn mul_base(&self) -> CtOption<Self::Output>;
}
