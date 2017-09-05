//! This crate defines a set of simple traits used to define functionality of
//! block ciphers.
#![no_std]
pub extern crate generic_array;

use generic_array::{GenericArray, ArrayLength};
use generic_array::typenum::Unsigned;

type Block<BlockSize> = GenericArray<u8, BlockSize>;

/// Main block cipher trait which defines in-place encryption and decryption
/// over single block
pub trait BlockCipher {
    type BlockSize: ArrayLength<u8>;

    /// Encrypt block in-place
    fn encrypt_block(&self, block: &mut Block<Self::BlockSize>);

    /// Decrypt block in-place
    fn decrypt_block(&self, block: &mut Block<Self::BlockSize>);

    /// Encrypt several blocks in-place. Will panic if slice length is not
    /// multiple of block size.
    ///
    /// Default implementations will just iterate over blocks and will use
    /// `encrypt_block` on them, but some ciphers could utilize instruction
    /// level parallelism to speed-up computations
    #[inline]
    fn encrypt_blocks(&self, blocks: &mut [u8]) {
        let bs = Self::BlockSize::to_usize();
        assert_eq!(blocks.len() % bs, 0,
            "blocks slice length is not multiple of block size");
        for block in blocks.chunks_mut(bs) {
            let block = unsafe {
                &mut *(block.as_mut_ptr() as *mut Block<Self::BlockSize>)
            };
            self.encrypt_block(block);
        }
    }

    /// Decrypt several blocks in-place. Will panic if slice length is not
    /// multiple of block size.
    ///
    /// Default implementations will just iterate over blocks and will use
    /// `decrypt_block` on them, but some ciphers could utilize instruction
    /// level parallelism to speed-up computations
    #[inline]
    fn decrypt_blocks(&self, blocks: &mut [u8]) {
        let bs = Self::BlockSize::to_usize();
        assert_eq!(blocks.len() % bs, 0,
            "blocks slice length is not multiple of block size");
        for block in blocks.chunks_mut(bs) {
            let block = unsafe {
                &mut *(block.as_mut_ptr() as *mut Block<Self::BlockSize>)
            };
            self.decrypt_block(block);
        }
    }
}

/// Trait for creation of block cipher with fixed size key
pub trait NewFixKey: BlockCipher {
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
pub trait NewVarKey: BlockCipher + Sized {
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
