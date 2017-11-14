//! This crate defines a set of simple traits used to define functionality of
//! block ciphers.
#![no_std]
pub extern crate generic_array;

use generic_array::{GenericArray, ArrayLength};
use generic_array::typenum::Unsigned;

#[cfg(feature = "dev")]
pub mod dev;

type ParBlocks<B, P> = GenericArray<GenericArray<u8, B>, P>;

/// The trait which defines in-place encryption and decryption
/// over single block or several blocks in parallel.
pub trait BlockCipher {
    /// Size of the block in bytes
    type BlockSize: ArrayLength<u8>;
    /// Number of blocks which can be processed in parallel by
    /// cipher implementation
    type ParBlocks: ArrayLength<GenericArray<u8, Self::BlockSize>>;

    /// Encrypt block in-place
    fn encrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>);

    /// Decrypt block in-place
    fn decrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>);

    /// Encrypt several blocks in parallel using instruction level parallelism
    /// if possible.
    ///
    /// If `ParBlocks` equals to 1 it's equivalent to `encrypt_block`.
    #[inline]
    fn encrypt_blocks(&self,
        blocks: &mut ParBlocks<Self::BlockSize, Self::ParBlocks>)
    {
        for block in blocks.iter_mut() { self.encrypt_block(block); }
    }

    /// Decrypt several blocks in parallel using instruction level parallelism
    /// if possible.
    ///
    /// If `ParBlocks` equals to 1 it's equivalent to `decrypt_block`.
    #[inline]
    fn decrypt_blocks(&self,
        blocks: &mut ParBlocks<Self::BlockSize, Self::ParBlocks>)
    {
        for block in blocks.iter_mut() { self.decrypt_block(block); }
    }
}

/// Trait for creation of block cipher with fixed size key
pub trait NewFixKey {
    type KeySize: ArrayLength<u8>;

    /// Create new block cipher instance with given fixed size key
    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self;
}

/// Error struct which used with `NewVarKey`
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct InvalidKeyLength;

/// Trait for creation of block cipher with variable size keys.
///
/// This trait is auto implemented for `NewFixKey`.
pub trait NewVarKey: Sized {
    /// Create new block cipher instance with given key, if length of given
    /// key is unsupported by implementation error will be returned.
    fn new(key: &[u8]) -> Result<Self, InvalidKeyLength>;
}

impl<T: NewFixKey> NewVarKey for T {
    fn new(key: &[u8]) -> Result<Self, InvalidKeyLength> {
        if key.len() != T::KeySize::to_usize() {
            Err(InvalidKeyLength)
        } else {
            Ok(T::new(GenericArray::from_slice(key)))
        }
    }
}
