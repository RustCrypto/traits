//! This crate defines a set of traits which define functionality of
//! stream ciphers.
//!
//! See [RustCrypto/stream-ciphers](https://github.com/RustCrypto/stream-ciphers)
//! for ciphers implementation.
#![no_std]
#![doc(html_logo_url =
    "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
pub extern crate generic_array;
#[cfg(feature = "dev")]
pub extern crate blobby;
#[cfg(feature = "std")]
extern crate std;

use generic_array::{GenericArray, ArrayLength};
use generic_array::typenum::Unsigned;

#[cfg(feature = "dev")]
pub mod dev;
mod errors;

pub use errors::{LoopError, InvalidKeyNonceLength};

/// Synchronous stream cipher core trait
pub trait StreamCipherCore {
    /// Apply keystream to the data.
    ///
    /// It will XOR generated keystream with the data, which can be both
    /// encryption and decryption.
    ///
    /// # Panics
    /// If end of the keystream will be reached with the given data length,
    /// method will panic without modifying the provided `data`.
    #[inline]
    fn apply_keystream(&mut self, data: &mut [u8]) {
        self.try_apply_keystream(data)
            .expect("stream cipher loop detected")
    }

    /// Apply keystream to the data, but return an error if end of a keystream
    /// will be reached.
    ///
    /// If end of the keystream will be achieved with the given data length,
    /// method will return `Err(LoopError)` without modifying provided `data`.
    fn try_apply_keystream(&mut self, data: &mut [u8]) -> Result<(), LoopError>;
}

/// Synchronous stream cipher seeking trait
pub trait StreamCipherSeek {
    /// Return current position of a keystream in bytes from the beginning.
    fn current_pos(&self) -> u64;
    /// Seek keystream to the given `pos` in bytes.
    fn seek(&mut self, pos: u64);
}

//TODO: rename to NewStreamCipher in next minor release
/// Synchronous stream cipher creation trait
pub trait NewFixStreamCipher: Sized {
    /// Key size in bytes
    type KeySize: ArrayLength<u8>;
    /// Nonce size in bytes
    type NonceSize: ArrayLength<u8>;

    /// Create new stream cipher instance from variable length key and nonce.
    fn new(
        key: &GenericArray<u8, Self::KeySize>,
        nonce: &GenericArray<u8, Self::NonceSize>,
    ) -> Self;

    /// Create new stream cipher instance from variable length key and nonce.
    fn new_var(key: &[u8], nonce: &[u8]) -> Result<Self, InvalidKeyNonceLength> {
        let kl = Self::KeySize::to_usize();
        let nl = Self::NonceSize::to_usize();
        if key.len() != kl || nonce.len() != nl {
            Err(InvalidKeyNonceLength)
        } else {
            let key = GenericArray::from_slice(key);
            let nonce = GenericArray::from_slice(nonce);
            Ok(Self::new(key, nonce))
        }
    }
}
