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
//!
//! [Universal Hash Functions]: https://en.wikipedia.org/wiki/Universal_hashing

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

pub use generic_array;

use generic_array::typenum::Unsigned;
use generic_array::{ArrayLength, GenericArray};
use subtle::{Choice, ConstantTimeEq};

/// The `UniversalHash` trait defines a generic interface for universal hash
/// functions.
pub trait UniversalHash: Clone {
    /// Size of the key for the universal hash function
    type KeySize: ArrayLength<u8>;
    /// Size of the inputs to and outputs from the universal hash function
    type BlockSize: ArrayLength<u8>;

    /// Instantiate a universal hash function with the given key
    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self;

    /// Input a block into the universal hash function
    fn update_block(&mut self, block: &GenericArray<u8, Self::BlockSize>);

    /// Input data into the universal hash function. If the length of the
    /// data is not a multiple of the block size, the remaining data is
    /// padded with zeroes up to the `BlockSize`.
    ///
    /// This approach is frequently used by AEAD modes which use
    /// Message Authentication Codes (MACs) based on universal hashing.
    fn update_padded(&mut self, data: &[u8]) {
        let mut chunks = data.chunks_exact(Self::BlockSize::to_usize());

        for chunk in &mut chunks {
            self.update_block(GenericArray::from_slice(chunk));
        }

        let rem = chunks.remainder();

        if !rem.is_empty() {
            let mut padded_block = GenericArray::default();
            padded_block[..rem.len()].copy_from_slice(rem);
            self.update_block(&padded_block);
        }
    }

    /// Reset `UniversalHash` instance.
    fn reset(&mut self);

    /// Obtain the [`Output`] of a `UniversalHash` function and consume it.
    fn result(self) -> Output<Self::BlockSize>;

    /// Obtain the [`Output`] of a `UniversalHash` computation and reset it back
    /// to its initial state.
    fn result_reset(&mut self) -> Output<Self::BlockSize> {
        let res = self.clone().result();
        self.reset();
        res
    }

    /// Verify the `UniversalHash` of the processed input matches a given [`Output`].
    /// This is useful when constructing Message Authentication Codes (MACs)
    /// from universal hash functions.
    fn verify(self, other: &GenericArray<u8, Self::BlockSize>) -> Result<(), Error> {
        if self.result() == other.into() {
            Ok(())
        } else {
            Err(Error)
        }
    }
}

/// Outputs of universal hash functions which are a thin wrapper around a
/// byte array. Provides a safe `Eq` implementation that runs in constant time,
/// which is useful for implementing Message Authentication Codes (MACs) based
/// on universal hashing.
#[derive(Clone)]
pub struct Output<N: ArrayLength<u8>> {
    bytes: GenericArray<u8, N>,
}

impl<N> Output<N>
where
    N: ArrayLength<u8>,
{
    /// Create a new `Block`.
    pub fn new(bytes: GenericArray<u8, N>) -> Output<N> {
        Output { bytes }
    }

    /// Get the inner `GenericArray` this type wraps
    pub fn into_bytes(self) -> GenericArray<u8, N> {
        self.bytes
    }
}

impl<N> From<GenericArray<u8, N>> for Output<N>
where
    N: ArrayLength<u8>,
{
    fn from(bytes: GenericArray<u8, N>) -> Self {
        Output { bytes }
    }
}

impl<'a, N> From<&'a GenericArray<u8, N>> for Output<N>
where
    N: ArrayLength<u8>,
{
    fn from(bytes: &'a GenericArray<u8, N>) -> Self {
        bytes.clone().into()
    }
}

impl<N> ConstantTimeEq for Output<N>
where
    N: ArrayLength<u8>,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.bytes.ct_eq(&other.bytes)
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

impl<N: ArrayLength<u8>> Eq for Output<N> {}

/// Error type for when the `Output` of a `UniversalHash`
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
