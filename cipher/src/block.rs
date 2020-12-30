//! Traits used to define functionality of [block ciphers][1].
//!
//! # About block ciphers
//!
//! Block ciphers are keyed, deterministic permutations of a fixed-sized input
//! "block" providing a reversible transformation to/from an encrypted output.
//! They are one of the fundamental structural components of [symmetric cryptography][2].
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher
//! [2]: https://en.wikipedia.org/wiki/Symmetric-key_algorithm

use crate::errors::InvalidLength;
use core::convert::TryInto;
use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};

/// Key for an algorithm that implements [`NewBlockCipher`].
pub type BlockCipherKey<B> = GenericArray<u8, <B as NewBlockCipher>::KeySize>;

/// Block on which a [`BlockCipher`] operates.
pub type Block<B> = GenericArray<u8, <B as BlockCipher>::BlockSize>;

/// Block on which a [`BlockCipher`] operates in parallel.
pub type ParBlocks<B> = GenericArray<Block<B>, <B as BlockCipher>::ParBlocks>;

/// Instantiate a [`BlockCipher`] algorithm.
pub trait NewBlockCipher: Sized {
    /// Key size in bytes with which cipher guaranteed to be initialized.
    type KeySize: ArrayLength<u8>;

    /// Create new block cipher instance from key with fixed size.
    fn new(key: &BlockCipherKey<Self>) -> Self;

    /// Create new block cipher instance from key with variable size.
    ///
    /// Default implementation will accept only keys with length equal to
    /// `KeySize`, but some ciphers can accept range of key lengths.
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        if key.len() != Self::KeySize::to_usize() {
            Err(InvalidLength)
        } else {
            Ok(Self::new(GenericArray::from_slice(key)))
        }
    }
}

/// Trait which marks a type as being a block cipher.
pub trait BlockCipher {
    /// Size of the block in bytes
    type BlockSize: ArrayLength<u8>;

    /// Number of blocks which can be processed in parallel by
    /// cipher implementation
    type ParBlocks: ArrayLength<Block<Self>>;
}

/// Encrypt-only functionality for block ciphers.
pub trait BlockEncrypt: BlockCipher {
    /// Encrypt block in-place
    fn encrypt_block(&self, block: &mut Block<Self>);

    /// Encrypt several blocks in parallel using instruction level parallelism
    /// if possible.
    ///
    /// If `ParBlocks` equals to 1 it's equivalent to `encrypt_block`.
    #[inline]
    fn encrypt_par_blocks(&self, blocks: &mut ParBlocks<Self>) {
        for block in blocks.iter_mut() {
            self.encrypt_block(block);
        }
    }

    /// Encrypt a slice of blocks, leveraging parallelism when available.
    #[inline]
    fn encrypt_blocks(&self, mut blocks: &mut [Block<Self>]) {
        let pb = Self::ParBlocks::to_usize();

        if pb > 1 {
            let mut iter = blocks.chunks_exact_mut(pb);

            for chunk in &mut iter {
                self.encrypt_par_blocks(chunk.try_into().unwrap())
            }

            blocks = iter.into_remainder();
        }

        for block in blocks {
            self.encrypt_block(block);
        }
    }
}

/// Decrypt-only functionality for block ciphers.
pub trait BlockDecrypt: BlockCipher {
    /// Decrypt block in-place
    fn decrypt_block(&self, block: &mut Block<Self>);

    /// Decrypt several blocks in parallel using instruction level parallelism
    /// if possible.
    ///
    /// If `ParBlocks` equals to 1 it's equivalent to `decrypt_block`.
    #[inline]
    fn decrypt_par_blocks(&self, blocks: &mut ParBlocks<Self>) {
        for block in blocks.iter_mut() {
            self.decrypt_block(block);
        }
    }

    /// Decrypt a slice of blocks, leveraging parallelism when available.
    #[inline]
    fn decrypt_blocks(&self, mut blocks: &mut [Block<Self>]) {
        let pb = Self::ParBlocks::to_usize();

        if pb > 1 {
            let mut iter = blocks.chunks_exact_mut(pb);

            for chunk in &mut iter {
                self.decrypt_par_blocks(chunk.try_into().unwrap())
            }

            blocks = iter.into_remainder();
        }

        for block in blocks {
            self.decrypt_block(block);
        }
    }
}

/// Encrypt-only functionality for block ciphers with mutable access to `self`.
///
/// The main use case for this trait is hardware encryption engines which
/// require `&mut self` access to an underlying hardware peripheral.
pub trait BlockEncryptMut: BlockCipher {
    /// Encrypt block in-place
    fn encrypt_block_mut(&mut self, block: &mut Block<Self>);
}

/// Decrypt-only functionality for block ciphers with mutable access to `self`.
///
/// The main use case for this trait is hardware encryption engines which
/// require `&mut self` access to an underlying hardware peripheral.
pub trait BlockDecryptMut: BlockCipher {
    /// Decrypt block in-place
    fn decrypt_block_mut(&mut self, block: &mut Block<Self>);
}

impl<Alg: BlockEncrypt> BlockEncryptMut for Alg {
    fn encrypt_block_mut(&mut self, block: &mut Block<Self>) {
        self.encrypt_block(block);
    }
}

impl<Alg: BlockDecrypt> BlockDecryptMut for Alg {
    fn decrypt_block_mut(&mut self, block: &mut Block<Self>) {
        self.decrypt_block(block);
    }
}

// Impls of block cipher traits for reference types

impl<Alg: BlockCipher> BlockCipher for &Alg {
    type BlockSize = Alg::BlockSize;
    type ParBlocks = Alg::ParBlocks;
}

impl<Alg: BlockEncrypt> BlockEncrypt for &Alg {
    #[inline]
    fn encrypt_block(&self, block: &mut Block<Self>) {
        Alg::encrypt_block(self, block);
    }

    #[inline]
    fn encrypt_par_blocks(&self, blocks: &mut ParBlocks<Self>) {
        Alg::encrypt_par_blocks(self, blocks);
    }

    #[inline]
    fn encrypt_blocks(&self, blocks: &mut [Block<Self>]) {
        Alg::encrypt_blocks(self, blocks);
    }
}

impl<Alg: BlockDecrypt> BlockDecrypt for &Alg {
    #[inline]
    fn decrypt_block(&self, block: &mut Block<Self>) {
        Alg::decrypt_block(self, block);
    }

    #[inline]
    fn decrypt_par_blocks(&self, blocks: &mut ParBlocks<Self>) {
        Alg::decrypt_par_blocks(self, blocks);
    }

    #[inline]
    fn decrypt_blocks(&self, blocks: &mut [Block<Self>]) {
        Alg::decrypt_blocks(self, blocks);
    }
}
