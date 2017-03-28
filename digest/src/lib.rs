#![no_std]
extern crate generic_array;
use generic_array::{GenericArray, ArrayLength};

/// Trait for processing input data
pub trait Input {
    type BlockSize: ArrayLength<u8>;

    /// Digest input data. This method can be called repeatedly
    /// for use with streaming messages.
    fn digest(&mut self, input: &[u8]);
}

/// Trait for returning digest result with the fixed size
pub trait FixedOutput {
    type OutputSize: ArrayLength<u8>;

    /// Retrieve the digest result. This method consumes digest instance.
    fn fixed_result(self) -> GenericArray<u8, Self::OutputSize>;
}

/// The error type for variable digest output
#[derive(Copy, Clone, Debug)]
pub struct InvalidLength;

#[must_use]
pub type VariableResult<'a> = Result<&'a [u8], InvalidLength>;

/// Trait for returning digest result with the varaible size
pub trait VariableOutput {

    /// Retrieve the digest result into provided buffer. Length of the output
    /// equals to the input buffer size. In case of invalid length
    /// `Err(InvalidLength)` will be returned.
    /// This method consumes digest instance.
    fn variable_result(self, buffer: &mut [u8]) -> VariableResult;
}

/// The Digest trait specifies an interface common to digest functions. It's a
/// convinience wrapper around `Input` and `FixedResult` traits
pub trait Digest: Input + FixedOutput {
    type OutputSize: ArrayLength<u8>;
    type BlockSize: ArrayLength<u8>;

    /// Digest input data. This method can be called repeatedly
    /// for use with streaming messages.
    fn input(&mut self, input: &[u8]);

    /// Retrieve the digest result. This method consumes digest instance.
    fn result(self) -> GenericArray<u8, <Self as Digest>::OutputSize>;
}

impl<T: Input + FixedOutput> Digest for T {
    type OutputSize = <T as FixedOutput>::OutputSize;
    type BlockSize = <T as Input>::BlockSize;

    fn input(&mut self, input: &[u8]) {
        self.digest(input);
    }

    fn result(self) -> GenericArray<u8, <T as Digest>::OutputSize> {
        self.fixed_result()
    }
}
