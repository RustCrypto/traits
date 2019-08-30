//! Traits for [Universal Hash Functions].
//!
//! Universal hash functions select from a "universal family" of possible
//! hash functions selected by a key. They are well suited to the purpose
//! of "one time authenticators" for a sequence of bytestring inputs,
//! as their construction has a number of desirable properties such as
//! pairwise independence as well as amenability to efficient implementations,
//! particularly when implemented using SIMD instructions.
//!
//! When combined with a cipher, such as in Galois/Counter Mode or the
//! Salsa20 family AEAD constructions, they can provide the core functionality
//! for a Message Authentication Code (MAC).

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

pub extern crate generic_array;
extern crate subtle;

use generic_array::{ArrayLength, GenericArray};
use subtle::{Choice, ConstantTimeEq};

/// The `UniversalHash` trait defines a generic interface for universal hash
/// functions.
pub trait UniversalHash<BlockSize: ArrayLength<u8>>: Clone
where
    BlockSize::ArrayType: Copy,
{
    /// Instantiate a universal hash function with the given key
    fn new(key: Block<BlockSize>) -> Self;

    /// Input a block into the universal hash function
    fn input_block(&mut self, block: Block<BlockSize>);

    /// Input data into the universal hash function. If the length of the
    /// data is not a multiple of the block size, the remaining data is
    /// padded with zeroes up to the `BlockSize`.
    ///
    /// This approach is frequently used by AEAD modes which use
    /// Message Authentication Codes (MACs) based on universal hashing.
    fn input_padded(&mut self, data: &[u8]) {
        let block_size = BlockSize::to_usize();

        for chunk in data.chunks(block_size) {
            if chunk.len() == block_size {
                let block_bytes = *GenericArray::from_slice(chunk);
                self.input_block(block_bytes.into());
            } else {
                // Copy the non-aligned chunk into a zero-filled array
                let mut padded_block = GenericArray::default();
                padded_block[..chunk.len()].copy_from_slice(chunk);
                self.input_block(padded_block.into());
            }
        }
    }

    /// Reset `UniversalHash` instance.
    fn reset(&mut self);

    /// Obtain the output `Block` of a `UniversalHash` function and consume it.
    fn result(self) -> Block<BlockSize>;

    /// Obtain the output `Block` of a `UniversalHash` computation and reset it back
    /// to its initial state.
    fn result_reset(&mut self) -> Block<BlockSize> {
        let res = self.clone().result();
        self.reset();
        res
    }

    /// Verify the `UniversalHash` of the processed input matches a given output
    /// `Block`. This is useful when constructing Message Authentication Codes (MACs)
    /// from universal hash functions.
    fn verify(self, output: Block<BlockSize>) -> Result<(), Error> {
        if self.result() == output {
            Ok(())
        } else {
            Err(Error)
        }
    }
}

/// The `Block` type is used as the input and output of a universal hash
/// function and provides a thin wrapper around a byte array.
///
/// It provides a safe `Eq` implementation that runs in constant time, which
/// is useful for implementing Message Authentication Codes (MACs) based on
/// universal hashing.
#[derive(Copy, Clone)]
pub struct Block<N: ArrayLength<u8>>
where
    N::ArrayType: Copy,
{
    bytes: GenericArray<u8, N>,
}

impl<N> Block<N>
where
    N: ArrayLength<u8>,
    N::ArrayType: Copy,
{
    /// Create a new `Block`.
    pub fn new(bytes: GenericArray<u8, N>) -> Block<N> {
        Block { bytes }
    }
}

impl<N> From<GenericArray<u8, N>> for Block<N>
where
    N: ArrayLength<u8>,
    N::ArrayType: Copy,
{
    fn from(bytes: GenericArray<u8, N>) -> Self {
        Block { bytes }
    }
}

impl<N> ConstantTimeEq for Block<N>
where
    N: ArrayLength<u8>,
    N::ArrayType: Copy,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl<N> PartialEq for Block<N>
where
    N: ArrayLength<u8>,
    N::ArrayType: Copy,
{
    fn eq(&self, x: &Block<N>) -> bool {
        self.ct_eq(x).unwrap_u8() == 1
    }
}

impl<N> Eq for Block<N>
where
    N: ArrayLength<u8>,
    N::ArrayType: Copy,
{
}

/// Error type for when the output `Block` of a `UniversalHash`
/// is not equal to the expected value.
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub struct Error;

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn description(&self) -> &'static str {
        "UHF output mismatch"
    }
}

#[cfg(feature = "std")]
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use std::error::Error;
        self.description().fmt(f)
    }
}
