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
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

pub use crypto_common::{
    self,
    generic_array,
    typenum::{self, consts},
    KeyInit, Key, Block, ParBlocks,
};

use typenum::Unsigned;
use generic_array::{GenericArray, ArrayLength};
use crypto_common::{BlockSizeUser, ParBlocksSizeUser};
use subtle::ConstantTimeEq;
use core::slice;

/// Trait implemented by UHF backends.
pub trait UhfBackend: ParBlocksSizeUser {
    /// Process single block.
    fn proc_block(&mut self, block: &Block<Self>);

    /// Process several blocks in parallel.
    #[inline(always)]
    fn proc_par_blocks(&mut self, blocks: &ParBlocks<Self>) {
        for block in blocks {
            self.proc_block(block);
        }
    }
}

/// Trait for [`UhfBackend`] users.
///
/// This trait is used to define rank-2 closures.
pub trait UhfClosure: BlockSizeUser {
    /// Execute closure with the provided block cipher backend.
    fn call<B: UhfBackend<BlockSize = Self::BlockSize>>(self, backend: &mut B);
}

/// The [`UniversalHash`] trait defines a generic interface for universal hash
/// functions.
pub trait UniversalHash: BlockSizeUser + Sized {
    /// Update hash function state using the provided rank-2 closure.
    fn update_with_backend(&mut self, f: impl UhfClosure<BlockSize = Self::BlockSize>);

    /// Update hash function state with the provided block.
    #[inline]
    fn update(&mut self, blocks: &[Block<Self>]) {
        struct Ctx<'a, BS: ArrayLength<u8>> {
            blocks: &'a [Block<Self>],
        }

        impl<'a, BS: ArrayLength<u8>> BlockSizeUser for Ctx<'a, BS> {
            type BlockSize = BS;
        }

        impl<'a, BS: ArrayLength<u8>> UhfClosure for Ctx<'a, BS> {
            #[inline(always)]
            fn call<B: UhfBackend<BlockSize = BS>>(self, backend: &mut B) {
                let pb = B::ParBlocksSize::USIZE;
                if pb > 1 {
                    let (par_blocks, tail) = to_blocks(self.blocks);
                    for par_block in par_blocks {
                        backend.proc_par_blocks(par_block);
                    }
                    for block in tail {
                        backend.proc_block(block);
                    }
                } else {
                    for block in self.blocks {
                        backend.proc_block(block);
                    }
                }
            }
        }

        self.update_with_backend(Ctx { blocks });
    }

    /// Input data into the universal hash function. If the length of the
    /// data is not a multiple of the block size, the remaining data is
    /// padded with zeroes up to the `BlockSize`.
    ///
    /// This approach is frequently used by AEAD modes which use
    /// Message Authentication Codes (MACs) based on universal hashing.
    fn update_padded(&mut self, data: &[u8]) {
        let (blocks, tail) = to_blocks(data);

        self.update(blocks);

        if !tail.is_empty() {
            let mut padded_block = GenericArray::default();
            padded_block[..tail.len()].copy_from_slice(tail);
            self.update(slice::from_ref(&padded_block));
        }
    }

    /// Reset [`UniversalHash`] instance.
    fn reset(&mut self);

    /// Obtain the [`Output`] of a [`UniversalHash`] function and consume it.
    fn finalize(self) -> Block<Self>;

    /// Obtain the [`Output`] of a [`UniversalHash`] computation and reset it back
    /// to its initial state.
    fn finalize_reset(&mut self) -> Block<Self>;

    /// Verify the [`UniversalHash`] of the processed input matches a given [`Output`].
    /// This is useful when constructing Message Authentication Codes (MACs)
    /// from universal hash functions.
    fn verify(self, other: &Block<Self>) -> Result<(), Error> {
        if self.finalize().ct_eq(other).unwrap_u8() == 1 {
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

/// Split message into slice of blocks and leftover tail.
// TODO: replace with `slice::as_chunks` on migration to const generics
#[inline(always)]
fn to_blocks<T, N: ArrayLength<T>>(data: &[T]) -> (&[GenericArray<T, N>], &[T]) {
    let nb = data.len() / N::USIZE;
    let (left, right) = data.split_at(nb * N::USIZE);
    let p = left.as_ptr() as *const GenericArray<T, N>;
    // SAFETY: we guarantee that `blocks` does not point outside of `data`
    // and `p` is valid for reads
    let blocks = unsafe { slice::from_raw_parts(p, nb) };
    (blocks, right)
}
