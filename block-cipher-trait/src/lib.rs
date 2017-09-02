//! This crate defines a simple trait used to define block ciphers
#![no_std]
extern crate generic_array;

use generic_array::{GenericArray, ArrayLength};
use generic_array::typenum::Unsigned;

pub type Block<BlockSize> = GenericArray<u8, BlockSize>;

pub trait BlockCipher {
    type BlockSize: ArrayLength<u8>;

    fn encrypt_block(&self, block: &mut Block<Self::BlockSize>);

    fn decrypt_block(&self, block: &mut Block<Self::BlockSize>);
}


#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct InvalidKeyLength;

pub trait BlockCipherFixKey: BlockCipher {
    type KeySize: ArrayLength<u8>;

    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self;
}

pub trait BlockCipherVarKey: BlockCipher + Sized {
    fn new(key: &[u8]) -> Result<Self, InvalidKeyLength>;
}

impl<B: BlockCipherFixKey> BlockCipherVarKey for B {
    fn new(key: &[u8]) -> Result<Self, InvalidKeyLength> {
        if key.len() != B::KeySize::to_usize() {
            Err(InvalidKeyLength)
        } else {
            Ok(B::new(GenericArray::from_slice(key)))
        }
    }
}
