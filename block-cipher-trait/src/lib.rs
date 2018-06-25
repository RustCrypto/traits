//! This crate defines a set of simple traits used to define functionality of
//! block ciphers.
#![no_std]
pub extern crate generic_array;

#[cfg(feature = "std")]
extern crate std;

use generic_array::{GenericArray, ArrayLength};
use generic_array::typenum::Unsigned;

mod errors;
#[cfg(feature = "dev")]
pub mod dev;

pub use errors::InvalidKeyLength;

type ParBlocks<B, P> = GenericArray<GenericArray<u8, B>, P>;

/// The trait which defines in-place encryption and decryption
/// over single block or several blocks in parallel.
pub trait BlockCipher: core::marker::Sized {
    /// Key size in bytes with which cipher guaranteed to be initialized
    type KeySize: ArrayLength<u8>;
    /// Size of the block in bytes
    type BlockSize: ArrayLength<u8>;
    /// Number of blocks which can be processed in parallel by
    /// cipher implementation
    type ParBlocks: ArrayLength<GenericArray<u8, Self::BlockSize>>;

    /// Create new block cipher instance from key with fixed size.
    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self;

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
