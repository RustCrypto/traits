//! This crate provides traits for describing funcionality of cryptographic hash
//! functions.
//!
//! By default std functionality in this crate disabled. (e.g. method for
//! hashing `Read`ers) To enable it turn on `std` feature in your `Cargo.toml`
//! for this crate.
#![cfg_attr(not(feature = "std"), no_std)]
extern crate generic_array;

#[cfg(feature = "std")]
use std as core;
use generic_array::{GenericArray, ArrayLength};

mod digest;

pub use digest::Digest;

// `process` is choosen to not overlap with `input` method in the digest trait
// change it on trait alias stabilization

/// Trait for processing input data
pub trait Input {
    /// Digest input data. This method can be called repeatedly
    /// for use with streaming messages.
    fn process(&mut self, input: &[u8]);
}

/// Trait to indicate that digest function processes data in blocks of size
/// `BlockSize`. Main usage of this trait is for implementing HMAC generically.
pub trait BlockInput {
    type BlockSize: ArrayLength<u8>;
}

/// Trait for returning digest result with the fixed size
pub trait FixedOutput {
    type OutputSize: ArrayLength<u8>;

    /// Retrieve the digest result. This method consumes digest instance.
    fn fixed_result(self) -> GenericArray<u8, Self::OutputSize>;
}

/// The error type for variable digest output
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InvalidLength;

/// Trait for returning digest result with the varaible size
pub trait VariableOutput {

    /// Retrieve the digest result into provided buffer. Length of the output
    /// equals to the input buffer size. In case of invalid length
    /// `Err(InvalidLength)` will be returned.
    /// This method consumes digest instance.
    fn variable_result(self, buffer: &mut [u8]) -> Result<&[u8], InvalidLength>;
}

/// Trait for decribing readers which are used to extract extendable output
/// from the resulting state of hash function.
pub trait XofReader: core::marker::Sized {
    /// Read output into the `buffer`. Can be called unlimited number of times.
    fn read(&mut self, buffer: &mut [u8]);
}

/// Trait which describes extendable output (XOF) of hash functions. Using this
/// trait you first need to get structure which implements `XofReader`, using
/// which you can read extendable output.
pub trait ExtendableOutput {
    type Reader: XofReader;

    /// Finalize hash function and return XOF reader
    fn xof_result(self) -> Self::Reader;
}

impl<D: ExtendableOutput> VariableOutput for D {
    fn variable_result(self, buffer: &mut [u8]) -> Result<&[u8], InvalidLength> {
        let mut reader = self.xof_result();
        reader.read(buffer);
        Ok(buffer)
    }
}
