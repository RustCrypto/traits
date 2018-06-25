//! This crate provides trait for Message Authentication Code (MAC) algorithms.
#![no_std]
extern crate constant_time_eq;
pub extern crate generic_array;

#[cfg(feature = "std")]
extern crate std;

use constant_time_eq::constant_time_eq;
use generic_array::{GenericArray, ArrayLength};
use generic_array::typenum::Unsigned;

mod errors;
#[cfg(feature = "dev")]
pub mod dev;

pub use errors::{InvalidKeyLength, MacError};

/// The `Mac` trait defines methods for a Message Authentication algorithm.
pub trait Mac: core::marker::Sized {
    type OutputSize: ArrayLength<u8>;
    type KeySize: ArrayLength<u8>;

    /// Create new MAC instance from key with fixed size.
    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self;

    /// Create new MAC instance from key with variable size.
    ///
    /// Default implementation will accept only keys with length equal to
    /// `KeySize`, but some MACs can accept range of key lengths.
    fn new_varkey(key: &[u8]) -> Result<Self, InvalidKeyLength> {
        if key.len() != Self::KeySize::to_usize() {
            Err(InvalidKeyLength)
        } else {
            Ok(Self::new(GenericArray::from_slice(key)))
        }
    }

    /// Process input data.
    fn input(&mut self, data: &[u8]);

    /// Obtain the result of a `Mac` computation as a `MacResult` and reset
    /// `Mac` instance.
    fn result(&mut self) -> MacResult<Self::OutputSize>;

    /// Check if code is correct for the processed input and reset
    /// `Mac` instance.
    fn verify(&mut self, code: &[u8]) -> Result<(), MacError> {
        let result = self.result();
        if result.is_equal(code) {
            Ok(())
        } else {
            Err(MacError)
        }
    }
}

/// `MacResult` is a thin wrapper around bytes array which provides a safe `Eq`
/// implementation that runs in a fixed time.
#[derive(Clone)]
pub struct MacResult<N: ArrayLength<u8>> {
    code: GenericArray<u8, N>
}

impl<N> MacResult<N> where N: ArrayLength<u8> {
    /// Create a new MacResult.
    pub fn new(code: GenericArray<u8, N>) -> MacResult<N> {
        MacResult { code }
    }

    /// Get the code value as a bytes array. Be very careful using this method,
    /// since incorrect use of the code value may permit timing attacks which
    /// defeat the security provided by the `Mac` trait.
    pub fn code(self) -> GenericArray<u8, N> {
        self.code
    }

    /// Check if equality to provided slice in constant time
    pub fn is_equal(&self, code: &[u8]) -> bool {
        if N::to_usize() != code.len() {
            false
        } else {
            let result = MacResult::new(GenericArray::clone_from_slice(code));
            self.eq(&result)
        }
    }
}

impl<N> PartialEq for MacResult<N> where N: ArrayLength<u8> {
    fn eq(&self, x: &MacResult<N>) -> bool {
        constant_time_eq(&self.code[..], &x.code[..])
    }
}

impl<N> Eq for MacResult<N> where N: ArrayLength<u8> { }
