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
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_root_url = "https://docs.rs/universal-hash/0.5.0"
)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

pub use generic_array::{self, typenum::consts};

use core::slice;
use generic_array::{typenum::Unsigned, GenericArray};

pub use crypto_common::{
    Block, BlockSizeUser, CtOutput, FixedOutput, FixedOutputReset, Key, KeyInit, KeySizeUser,
    Output, Reset, UpdateCore,
};

/// The [`UniversalHash`] trait defines a generic interface for universal hash
/// functions.
pub trait UniversalHash: KeyInit + UpdateCore + FixedOutput {
    /// Input data into the universal hash function. If the length of the
    /// data is not a multiple of the block size, the remaining data is
    /// padded with zeroes up to the `BlockSize`.
    ///
    /// This approach is frequently used by AEAD modes which use
    /// Message Authentication Codes (MACs) based on universal hashing.
    fn update_padded(&mut self, data: &[u8]) {
        // TODO: replace with `array_chunks` on migration to const generics
        let (blocks, tail) = unsafe {
            let blocks_len = data.len() / Self::BlockSize::USIZE;
            let tail_start = Self::BlockSize::USIZE * blocks_len;
            let tail_len = data.len() - tail_start;
            (
                slice::from_raw_parts(data.as_ptr() as *const Block<Self>, blocks_len),
                slice::from_raw_parts(data.as_ptr().add(tail_start), tail_len),
            )
        };

        self.update_blocks(blocks);

        if !tail.is_empty() {
            let mut padded_block = GenericArray::default();
            padded_block[..tail.len()].copy_from_slice(tail);
            self.update_blocks(slice::from_ref(&padded_block));
        }
    }

    /// Obtain the [`Output`] of a [`UniversalHash`] function and consume it.
    fn finalize(self) -> CtOutput<Self> {
        CtOutput::new(self.finalize_fixed())
    }

    /// Obtain the [`Output`] of a [`UniversalHash`] computation and reset it back
    /// to its initial state.
    #[inline]
    fn finalize_reset(&mut self) -> CtOutput<Self>
    where
        Self: FixedOutputReset,
    {
        CtOutput::new(self.finalize_fixed_reset())
    }

    /// Verify the [`UniversalHash`] of the processed input matches a given [`Output`].
    /// This is useful when constructing Message Authentication Codes (MACs)
    /// from universal hash functions.
    fn verify(self, other: &Output<Self>) -> Result<(), Error> {
        if self.finalize() == other.into() {
            Ok(())
        } else {
            Err(Error)
        }
    }
}

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
