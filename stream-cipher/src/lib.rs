//! This crate defines a set of simple traits used to define functionality of
//! stream ciphers.
#![no_std]
pub extern crate generic_array;

use generic_array::{GenericArray, ArrayLength};

#[derive(Copy, Clone, Debug)]
pub struct LoopError;

/// Synchronous stream cipher core trait
pub trait StreamCipherCore {
    #[inline]
    fn apply_keystream(&mut self, data: &mut [u8]) {
        self.try_apply_keystream(data)
            .expect("stream cipher loop detected")
    }

    fn try_apply_keystream(&mut self, data: &mut [u8]) -> Result<(), LoopError>;
}

pub trait StreamCipherSeek {
    fn current_pos(&self) -> u64;
    fn seek(&mut self, pos: u64);
}

pub trait NewFixStreamCipher {
    type KeySize: ArrayLength<u8>;
    type NonceSize: ArrayLength<u8>;

    fn new(
        key: &GenericArray<u8, Self::KeySize>,
        nonce: &GenericArray<u8, Self::NonceSize>,
    ) -> Self;
}
