//! Traits for arithmetic operations on elliptic curve field elements.

pub use core::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

use crypto_bigint::{ArrayEncoding, ByteArray, Integer};
use subtle::CtOption;

/// Perform an inversion on a field element (i.e. base field element or scalar)
pub trait Invert {
    /// Field element type
    type Output;

    /// Invert a field element.
    fn invert(&self) -> CtOption<Self::Output>;
}

#[cfg(feature = "arithmetic")]
impl<F: ff::Field> Invert for F {
    type Output = F;

    fn invert(&self) -> CtOption<F> {
        ff::Field::invert(self)
    }
}

/// Modular reduction.
pub trait Reduce<UInt: Integer + ArrayEncoding>: Sized {
    /// Perform a modular reduction, returning a field element.
    fn from_uint_reduced(n: UInt) -> Self;

    /// Interpret the given byte array as a big endian integer and perform a
    /// modular reduction.
    fn from_be_bytes_reduced(bytes: ByteArray<UInt>) -> Self {
        Self::from_uint_reduced(UInt::from_be_byte_array(bytes))
    }

    /// Interpret the given byte array as a big endian integer and perform a
    /// modular reduction.
    fn from_le_bytes_reduced(bytes: ByteArray<UInt>) -> Self {
        Self::from_uint_reduced(UInt::from_le_byte_array(bytes))
    }
}
