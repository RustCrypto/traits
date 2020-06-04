//! Traits for [Universal Hash Functions].
//!
//! # About universal hashes
//!
//! Universal hash functions provide a "universal family" of possible
//! hash functions where a given member of a family is selected by a key.
//!
//! They are well suited to the purpose of "one time authenticators" for a
//! sequence of bytestring inputs, as their construction has a number of
//! desirable properties such as pairwise independence as well as amenability
//! to efficient implementations, particularly when implemented using SIMD
//! instructions.
//!
//! When combined with a cipher, such as in Galois/Counter Mode (GCM) or the
//! Salsa20 family AEAD constructions, they can provide the core functionality
//! for a Message Authentication Code (MAC).
//!
//! [Universal Hash Functions]: https://en.wikipedia.org/wiki/Universal_hashing

#![no_std]
#![forbid(unsafe_code)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

pub use generic_array::{self, typenum::consts};

use generic_array::typenum::Unsigned;
use generic_array::{ArrayLength, GenericArray};
use subtle::{Choice, ConstantTimeEq};

/// Keys to a [`UniversalHash`].
pub type Key<U> = GenericArray<u8, <U as NewUniversalHash>::KeySize>;

/// Blocks are inputs to a [`UniversalHash`].
pub type Block<U> = GenericArray<u8, <U as UniversalHash>::BlockSize>;

/// Instantiate a [`UniversalHash`] algorithm.
pub trait NewUniversalHash: Sized {
    /// Size of the key for the universal hash function.
    type KeySize: ArrayLength<u8>;

    /// Instantiate a universal hash function with the given key.
    fn new(key: &Key<Self>) -> Self;
}

/// The [`UniversalHash`] trait defines a generic interface for universal hash
/// functions.
pub trait UniversalHash: Clone {
    /// Size of the inputs to and outputs from the universal hash function
    type BlockSize: ArrayLength<u8>;

    /// Input a block into the universal hash function
    fn update(&mut self, block: &Block<Self>);

    /// Input data into the universal hash function. If the length of the
    /// data is not a multiple of the block size, the remaining data is
    /// padded with zeroes up to the `BlockSize`.
    ///
    /// This approach is frequently used by AEAD modes which use
    /// Message Authentication Codes (MACs) based on universal hashing.
    fn update_padded(&mut self, data: &[u8]) {
        let mut chunks = data.chunks_exact(Self::BlockSize::to_usize());

        for chunk in &mut chunks {
            self.update(GenericArray::from_slice(chunk));
        }

        let rem = chunks.remainder();

        if !rem.is_empty() {
            let mut padded_block = GenericArray::default();
            padded_block[..rem.len()].copy_from_slice(rem);
            self.update(&padded_block);
        }
    }

    /// Reset [`UniversalHash`] instance.
    fn reset(&mut self);

    /// Obtain the [`Output`] of a [`UniversalHash`] function and consume it.
    fn finalize(self) -> Output<Self>;

    /// Obtain the [`Output`] of a [`UniversalHash`] computation and reset it back
    /// to its initial state.
    fn finalize_reset(&mut self) -> Output<Self> {
        let res = self.clone().finalize();
        self.reset();
        res
    }

    /// Verify the [`UniversalHash`] of the processed input matches a given [`Output`].
    /// This is useful when constructing Message Authentication Codes (MACs)
    /// from universal hash functions.
    fn verify(self, other: &Block<Self>) -> Result<(), Error> {
        if self.finalize() == other.into() {
            Ok(())
        } else {
            Err(Error)
        }
    }
}

/// Outputs of universal hash functions which are a thin wrapper around a
/// byte array. Provides a safe [`Eq`] implementation that runs in constant time,
/// which is useful for implementing Message Authentication Codes (MACs) based
/// on universal hashing.
#[derive(Clone)]
pub struct Output<U: UniversalHash> {
    bytes: GenericArray<u8, U::BlockSize>,
}

impl<U> Output<U>
where
    U: UniversalHash,
{
    /// Create a new [`Output`] block.
    pub fn new(bytes: Block<U>) -> Output<U> {
        Output { bytes }
    }

    /// Get the inner [`GenericArray`] this type wraps
    pub fn into_bytes(self) -> Block<U> {
        self.bytes
    }
}

impl<U> From<Block<U>> for Output<U>
where
    U: UniversalHash,
{
    fn from(bytes: Block<U>) -> Self {
        Output { bytes }
    }
}

impl<'a, U> From<&'a Block<U>> for Output<U>
where
    U: UniversalHash,
{
    fn from(bytes: &'a Block<U>) -> Self {
        bytes.clone().into()
    }
}

impl<U> ConstantTimeEq for Output<U>
where
    U: UniversalHash,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl<U> PartialEq for Output<U>
where
    U: UniversalHash,
{
    fn eq(&self, x: &Output<U>) -> bool {
        self.ct_eq(x).unwrap_u8() == 1
    }
}

impl<U: UniversalHash> Eq for Output<U> {}

/// Error type for when the [`Output`] of a [`UniversalHash`]
/// is not equal to the expected value.
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub struct Error;

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("UHF output mismatch")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
