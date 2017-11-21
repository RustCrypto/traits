//! This crate provides traits for describing funcionality of cryptographic hash
//! functions.
//!
//! By default std functionality in this crate disabled. (e.g. method for
//! hashing `Read`ers) To enable it turn on `std` feature in your `Cargo.toml`
//! for this crate.
#![cfg_attr(not(feature = "std"), no_std)]
pub extern crate generic_array;

#[cfg(feature = "std")]
use std as core;
use generic_array::{GenericArray, ArrayLength};

mod digest;
#[cfg(feature = "dev")]
pub mod dev;

pub use digest::Digest;

// `process` is choosen to not overlap with `input` method in the digest trait
// change it on trait alias stabilization

/// Trait for processing input data
pub trait Input {
    /// Digest input data. This method can be called repeatedly, e.g. for
    /// processing streaming messages.
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

    /// Retrieve result and reset hasher instance.
    fn fixed_result(&mut self) -> GenericArray<u8, Self::OutputSize>;
}

/// The error type for variable hasher initialization
#[derive(Clone, Copy, Debug, Default)]
pub struct InvalidOutputSize;

/// The error type for variable hasher result
#[derive(Clone, Copy, Debug, Default)]
pub struct InvalidBufferLength;

/// Trait for returning digest result with the varaible size
pub trait VariableOutput: core::marker::Sized {
    /// Create new hasher instance with given output size. Will return
    /// `Err(InvalidOutputSize)` in case if hasher can not work with the given
    /// output size. Will always return an error if output size equals to zero.
    fn new(output_size: usize) -> Result<Self, InvalidOutputSize>;

    /// Get output size of the hasher instance provided to the `new` method
    fn output_size(&self) -> usize;

    /// Retrieve result into provided buffer and reset hasher instance.
    ///
    /// Length of the buffer must be equal to output size provided to the `new`
    /// method, otherwise `Err(InvalidBufferLength)` will be returned without
    /// resetting hasher.
    fn variable_result(&mut self, buffer: &mut [u8])
        -> Result<&[u8], InvalidBufferLength>;
}

/// Trait for decribing readers which are used to extract extendable output
/// from the resulting state of hash function.
pub trait XofReader {
    /// Read output into the `buffer`. Can be called unlimited number of times.
    fn read(&mut self, buffer: &mut [u8]);
}

/// Trait which describes extendable output (XOF) of hash functions. Using this
/// trait you first need to get structure which implements `XofReader`, using
/// which you can read extendable output.
pub trait ExtendableOutput {
    type Reader: XofReader;

    /// Retrieve XOF reader and reset hasher instance.
    fn xof_result(&mut self) -> Self::Reader;
}
