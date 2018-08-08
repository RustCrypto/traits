//! This crate defines a set of traits which define functionality of
//! stream ciphers.
//!
//! See [RustCrypto/stream-ciphers](https://github.com/RustCrypto/stream-ciphers)
//! for ciphers implementation.
#![no_std]
pub extern crate generic_array;

#[cfg(feature = "std")]
extern crate std;

use generic_array::{GenericArray, ArrayLength};
use core::fmt;

#[cfg(feature = "dev")]
pub mod dev;

/// Error which notifies that stream cipher has reached the end of a keystream.
#[derive(Copy, Clone, Debug)]
pub struct LoopError;

impl fmt::Display for LoopError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.write_str("Loop Error")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LoopError {}

/// Synchronous stream cipher core trait
pub trait StreamCipherCore {
    /// Apply keystream to the data.
    ///
    /// It will XOR generated keystream with the data, which can be both
    /// encryption and decryption.
    ///
    /// # Panics
    /// If end of the keystream will be achieved with the given data length,
    /// method will panic without modifiyng the provided `data`.
    #[inline]
    fn apply_keystream(&mut self, data: &mut [u8]) {
        self.try_apply_keystream(data)
            .expect("stream cipher loop detected")
    }

    /// Apply keystream to the data, but return an error if end of a keystream
    /// will be reached.
    ///
    /// If end of the keystream will be achieved with the given data length,
    /// method will return `Err(LoopError)` without modifiyng provided `data`.
    fn try_apply_keystream(&mut self, data: &mut [u8]) -> Result<(), LoopError>;
}

/// Synchronous stream cipher seeking trait
pub trait StreamCipherSeek {
    /// Return current position of a keystream in bytes from the beginning.
    fn current_pos(&self) -> u64;
    /// Seek keystream to the given `pos` in bytes.
    fn seek(&mut self, pos: u64);
}

/// Synchronous stream cipher creation trait
pub trait NewFixStreamCipher {
    /// Key size in bytes
    type KeySize: ArrayLength<u8>;
    /// Nonce size in bytes
    type NonceSize: ArrayLength<u8>;

    /// Create new stream cipher instance
    fn new(
        key: &GenericArray<u8, Self::KeySize>,
        nonce: &GenericArray<u8, Self::NonceSize>,
    ) -> Self;
}
