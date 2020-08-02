//! Traits for arithmetic operations on elliptic curve field elements

use subtle::CtOption;

/// Perform an inversion on a field element (i.e. base field element or scalar)
pub trait Invert {
    /// Field element type
    type Output;

    /// Invert a field element.
    fn invert(&self) -> CtOption<Self::Output>;
}
