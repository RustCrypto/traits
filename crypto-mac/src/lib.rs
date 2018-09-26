//! This crate provides trait for Message Authentication Code (MAC) algorithms.
#![no_std]
#![doc(html_logo_url =
    "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
extern crate subtle;
pub extern crate generic_array;

#[cfg(feature = "std")]
extern crate std;
#[cfg(feature = "dev")]
pub extern crate blobby;

use subtle::{Choice, ConstantTimeEq};
use generic_array::{GenericArray, ArrayLength};
use generic_array::typenum::Unsigned;

mod errors;
#[cfg(feature = "dev")]
pub mod dev;

pub use errors::{InvalidKeyLength, MacError};

/// The `Mac` trait defines methods for a Message Authentication algorithm.
pub trait Mac: Clone {
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

    /// Reset `Mac` instance.
    fn reset(&mut self);

    /// Obtain the result of a `Mac` computation as a `MacResult` and consume
    /// `Mac` instance.
    fn result(self) -> MacResult<Self::OutputSize>;

    /// Obtain the result of a `Mac` computation as a `MacResult` and reset
    /// `Mac` instance.
    fn result_reset(&mut self) -> MacResult<Self::OutputSize> {
        let res = self.clone().result();
        self.reset();
        res
    }

    /// Check if code is correct for the processed input.
    fn verify(self, code: &[u8]) -> Result<(), MacError> {
        let choice = self.result().code.ct_eq(code);
        if choice.unwrap_u8() == 1 {
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

    /// Get the code value as a bytes array.
    ///
    /// Be very careful using this method, since incorrect use of the code value
    /// may permit timing attacks which defeat the security provided by the
    /// `Mac` trait.
    pub fn code(self) -> GenericArray<u8, N> {
        self.code
    }
}

impl<N> ConstantTimeEq for MacResult<N> where N: ArrayLength<u8> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.code.ct_eq(&other.code)
    }
}

impl<N> PartialEq for MacResult<N> where N: ArrayLength<u8> {
    fn eq(&self, x: &MacResult<N>) -> bool {
        self.ct_eq(x).unwrap_u8() == 1
    }
}

impl<N> Eq for MacResult<N> where N: ArrayLength<u8> { }
