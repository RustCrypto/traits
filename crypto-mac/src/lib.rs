//! This crate provides trait for Message Authentication Code (MAC) algorithms.

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "dev")]
pub mod dev;

mod errors;

pub use crate::errors::{InvalidKeyLength, MacError};
pub use generic_array::{self, typenum::consts};

use generic_array::typenum::Unsigned;
use generic_array::{ArrayLength, GenericArray};
use subtle::{Choice, ConstantTimeEq};

/// The [`Mac`] trait defines methods for a Message Authentication algorithm.
pub trait Mac: Clone {
    /// Output size of the [[`Mac`]]
    type OutputSize: ArrayLength<u8>;

    /// Keys size of the [[`Mac`]]
    type KeySize: ArrayLength<u8>;

    /// Initialize new MAC instance from key with fixed size.
    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self;

    /// Initialize new MAC instance from key with variable size.
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

    /// Update MAC state with the given data.
    fn update(&mut self, data: &[u8]);

    /// Reset [`Mac`] instance.
    fn reset(&mut self);

    /// Obtain the result of a [`Mac`] computation as a [`Output`] and consume
    /// [`Mac`] instance.
    fn result(self) -> Output<Self::OutputSize>;

    /// Obtain the result of a [`Mac`] computation as a [`Output`] and reset
    /// [`Mac`] instance.
    fn result_reset(&mut self) -> Output<Self::OutputSize> {
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

/// [`Output`] is a thin wrapper around bytes array which provides a safe `Eq`
/// implementation that runs in a fixed time.
#[derive(Clone)]
pub struct Output<N: ArrayLength<u8>> {
    code: GenericArray<u8, N>,
}

impl<N> Output<N>
where
    N: ArrayLength<u8>,
{
    /// Create a new MAC [`Output`].
    pub fn new(code: GenericArray<u8, N>) -> Output<N> {
        Output { code }
    }

    /// Get the MAC code/tag value as a byte array.
    ///
    /// Be very careful using this method, since incorrect use of the code value
    /// may permit timing attacks which defeat the security provided by the
    /// [`Mac`] trait.
    pub fn into_bytes(self) -> GenericArray<u8, N> {
        self.code
    }
}

impl<N> ConstantTimeEq for Output<N>
where
    N: ArrayLength<u8>,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.code.ct_eq(&other.code)
    }
}

impl<N> PartialEq for Output<N>
where
    N: ArrayLength<u8>,
{
    fn eq(&self, x: &Output<N>) -> bool {
        self.ct_eq(x).unwrap_u8() == 1
    }
}

impl<N> Eq for Output<N> where N: ArrayLength<u8> {}
