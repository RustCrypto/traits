//! This crate defines a set of traits which define functionality of
//! stream ciphers.
//!
//! See [RustCrypto/stream-ciphers](https://github.com/RustCrypto/stream-ciphers)
//! for ciphers implementation.
#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#[cfg(feature = "dev")]
pub extern crate blobby;
pub extern crate generic_array;
#[cfg(feature = "std")]
extern crate std;

use generic_array::typenum::Unsigned;
use generic_array::{ArrayLength, GenericArray};

#[cfg(feature = "dev")]
pub mod dev;
mod errors;

pub use errors::{InvalidKeyNonceLength, LoopError};

/// Stream cipher creation trait.
///
/// It can be used for creation of synchronous and asynchronous ciphers.
pub trait NewStreamCipher: Sized {
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
    #[inline]
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

/// Synchronous stream cipher core trait.
pub trait SyncStreamCipher {
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
        let res = self.try_apply_keystream(data);
        if res.is_err() {
            panic!("stream cipher loop detected");
        }
    }

    /// Apply keystream to the data, but return an error if end of a keystream
    /// will be reached.
    ///
    /// If end of the keystream will be achieved with the given data length,
    /// method will return `Err(LoopError)` without modifying provided `data`.
    fn try_apply_keystream(&mut self, data: &mut [u8]) -> Result<(), LoopError>;
}

/// Synchronous stream cipher seeking trait.
pub trait SyncStreamCipherSeek {
    /// Return current position of a keystream in bytes from the beginning.
    fn current_pos(&self) -> u64;

    /// Seek keystream to the given `pos` in bytes.
    fn seek(&mut self, pos: u64);
}

/// Stream cipher core trait which covers both synchronous and asynchronous
/// ciphers.
///
/// Note that for synchronous ciphers `encrypt` and `decrypt` are equivalent to
/// each other.
pub trait StreamCipher {
    /// Encrypt data in place.
    fn encrypt(&mut self, data: &mut [u8]);

    /// Decrypt data in place.
    fn decrypt(&mut self, data: &mut [u8]);
}

impl<C: SyncStreamCipher> StreamCipher for C {
    #[inline(always)]
    fn encrypt(&mut self, data: &mut [u8]) {
        SyncStreamCipher::apply_keystream(self, data);
    }

    #[inline(always)]
    fn decrypt(&mut self, data: &mut [u8]) {
        SyncStreamCipher::apply_keystream(self, data);
    }
}
