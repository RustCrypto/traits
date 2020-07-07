//! This crate defines a set of simple traits used to define functionality of
//! [block ciphers][1].
//!
//! # About block ciphers
//!
//! Block ciphers are keyed, deterministic permutations of a fixed-sized input
//! "block" providing a reversible transformation to/from an encrypted output.
//! They are one of the fundamental structural components of [symmetric cryptography][2].
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher
//! [2]: https://en.wikipedia.org/wiki/Symmetric-key_algorithm

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "dev")]
#[cfg_attr(docsrs, doc(cfg(feature = "dev")))]
pub mod dev;

mod errors;

pub use crate::errors::InvalidKeyLength;
pub use generic_array::{self, typenum::consts};

use generic_array::typenum::Unsigned;
use generic_array::{ArrayLength, GenericArray};

/// Key for an algorithm that implements [`NewBlockCipher`].
pub type Key<B> = GenericArray<u8, <B as NewBlockCipher>::KeySize>;

/// Block on which a [`BlockCipher`] operates.
pub type Block<B> = GenericArray<u8, <B as BlockCipher>::BlockSize>;

/// Blocks being acted over in parallel.
pub type ParBlocks<B> = GenericArray<Block<B>, <B as BlockCipher>::ParBlocks>;

/// Instantiate a [`BlockCipher`] algorithm.
pub trait NewBlockCipher: Sized {
    /// Key size in bytes with which cipher guaranteed to be initialized.
    type KeySize: ArrayLength<u8>;

    /// Create new block cipher instance from key with fixed size.
    fn new(key: &Key<Self>) -> Self;

    /// Create new block cipher instance from key with variable size.
    ///
    /// Default implementation will accept only keys with length equal to
    /// `KeySize`, but some ciphers can accept range of key lengths.
    fn new_varkey(key: &[u8]) -> Result<Self, InvalidKeyLength> {
        if key.len() != Self::KeySize::to_usize() {
            Err(InvalidKeyLength)
        } else {
            Ok(Self::new(GenericArray::from_slice(key)))
        }
    }
}

/// The trait which defines in-place encryption and decryption
/// over single block or several blocks in parallel.
pub trait BlockCipher {
    /// Size of the block in bytes
    type BlockSize: ArrayLength<u8>;

    /// Number of blocks which can be processed in parallel by
    /// cipher implementation
    type ParBlocks: ArrayLength<Block<Self>>;

    /// Encrypt block in-place
    fn encrypt_block(&self, block: &mut Block<Self>);

    /// Decrypt block in-place
    fn decrypt_block(&self, block: &mut Block<Self>);

    /// Encrypt several blocks in parallel using instruction level parallelism
    /// if possible.
    ///
    /// If `ParBlocks` equals to 1 it's equivalent to `encrypt_block`.
    #[inline]
    fn encrypt_blocks(&self, blocks: &mut ParBlocks<Self>) {
        for block in blocks.iter_mut() {
            self.encrypt_block(block);
        }
    }

    /// Decrypt several blocks in parallel using instruction level parallelism
    /// if possible.
    ///
    /// If `ParBlocks` equals to 1 it's equivalent to `decrypt_block`.
    #[inline]
    fn decrypt_blocks(&self, blocks: &mut ParBlocks<Self>) {
        for block in blocks.iter_mut() {
            self.decrypt_block(block);
        }
    }
}

/// Stateful block cipher which permits `&mut self` access.
///
/// The main use case for this trait is hardware encryption engines which
/// require `&mut self` access to an underlying hardware peripheral.
pub trait BlockCipherMut {
    /// Size of the block in bytes
    type BlockSize: ArrayLength<u8>;

    /// Encrypt block in-place
    fn encrypt_block(&mut self, block: &mut GenericArray<u8, Self::BlockSize>);

    /// Decrypt block in-place
    fn decrypt_block(&mut self, block: &mut GenericArray<u8, Self::BlockSize>);
}

impl<Alg: BlockCipher> BlockCipherMut for Alg {
    type BlockSize = Alg::BlockSize;

    #[inline]
    fn encrypt_block(&mut self, block: &mut GenericArray<u8, Self::BlockSize>) {
        <Self as BlockCipher>::encrypt_block(self, block);
    }

    #[inline]
    fn decrypt_block(&mut self, block: &mut GenericArray<u8, Self::BlockSize>) {
        <Self as BlockCipher>::decrypt_block(self, block);
    }
}

impl<Alg: BlockCipher> BlockCipher for &Alg {
    type BlockSize = Alg::BlockSize;
    type ParBlocks = Alg::ParBlocks;

    #[inline]
    fn encrypt_block(&self, block: &mut Block<Self>) {
        Alg::encrypt_block(self, block);
    }

    #[inline]
    fn decrypt_block(&self, block: &mut Block<Self>) {
        Alg::decrypt_block(self, block);
    }

    #[inline]
    fn encrypt_blocks(&self, blocks: &mut ParBlocks<Self>) {
        Alg::encrypt_blocks(self, blocks);
    }

    #[inline]
    fn decrypt_blocks(&self, blocks: &mut ParBlocks<Self>) {
        Alg::decrypt_blocks(self, blocks);
    }
}
