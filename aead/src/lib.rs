//! Authenticated Encryption with Associated Data (AEAD) traits
//!
//! This crate provides an abstract interface for AEAD ciphers, which guarantee
//! both confidentiality and integrity, even from a powerful attacker who is
//! able to execute [chosen-ciphertext attacks]. The resulting security property,
//! [ciphertext indistinguishability], is considered a basic requirement for
//! modern cryptographic implementations.
//!
//! See [RustCrypto/AEADs] for cipher implementations which use this trait.
//!
//! [chosen-ciphertext attacks]: https://en.wikipedia.org/wiki/Chosen-ciphertext_attack
//! [ciphertext indistinguishability]: https://en.wikipedia.org/wiki/Ciphertext_indistinguishability
//! [RustCrypto/AEADs]: https://github.com/RustCrypto/AEADs

#![no_std]

extern crate alloc;

pub use generic_array;

use alloc::vec::Vec;
use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Error;

/// Instantiate either a stateless [`Aead`] or stateful [`AeadMut`] algorithm.
pub trait NewAead {
    /// The size of the key array required by this algorithm.
    type KeySize: ArrayLength<u8>;

    /// Construct a new stateful instance for the given key.
    fn new(key: GenericArray<u8, Self::KeySize>) -> Self;
}

/// Authenticated Encryption with Associated Data (AEAD) algorithm.
///
/// This trait is intended for use with stateless AEAD algorithms. The
/// `AeadMut` trait provides a stateful interface.
pub trait Aead {
    /// The length of a nonce.
    type NonceSize: ArrayLength<u8>;
    /// The maximum length of the nonce.
    type TagSize: ArrayLength<u8>;
    /// The upper bound amount of additional space required to support a
    /// ciphertext vs. a plaintext.
    type CiphertextOverhead: ArrayLength<u8> + Unsigned;

    /// Encrypt the given plaintext payload, and return the resulting
    /// ciphertext as a vector of bytes.
    ///
    /// The [`Payload`] type can be used to provide Additional Associated Data
    /// (AAD) along with the message: this is an optional bytestring which is
    /// not encrypted, but *is* authenticated along with the message. Failure
    /// to pass the same AAD that was used during encryption will cause
    /// decryption to fail, which is useful if you would like to "bind" the
    /// ciphertext to some other identifier, like a digital signature key
    /// or other identifier.
    ///
    /// If you don't care about AAD and just want to encrypt a plaintext
    /// message, `&[u8]` will automatically be coerced into a `Payload`:
    ///
    /// ```nobuild
    /// let plaintext = b"Top secret message, handle with care";
    /// let ciphertext = cipher.encrypt(nonce, plaintext);
    /// ```
    fn encrypt<'msg, 'aad>(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error>;

    /// Decrypt the given ciphertext slice, and return the resulting plaintext
    /// as a vector of bytes.
    ///
    /// See notes on [`Aead::encrypt()`] about allowable message payloads and
    /// Associated Additional Data (AAD).
    ///
    /// If you have no AAD, you can call this as follows:
    ///
    /// ```nobuild
    /// let ciphertext = b"...";
    /// let plaintext = cipher.decrypt(nonce, ciphertext)?;
    /// ```
    fn decrypt<'msg, 'aad>(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error>;
}

/// Stateful Authenticated Encryption with Associated Data algorithm.
pub trait AeadMut {
    /// The length of a nonce.
    type NonceSize: ArrayLength<u8>;
    /// The maximum length of the nonce.
    type TagSize: ArrayLength<u8>;
    /// The upper bound amount of additional space required to support a
    /// ciphertext vs. a plaintext.
    type CiphertextOverhead: ArrayLength<u8> + Unsigned;

    /// Encrypt the given plaintext slice, and return the resulting ciphertext
    /// as a vector of bytes.
    ///
    /// See notes on [`Aead::encrypt()`] about allowable message payloads and
    /// Associated Additional Data (AAD).
    fn encrypt<'msg, 'aad>(
        &mut self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error>;

    /// Decrypt the given ciphertext slice, and return the resulting plaintext
    /// as a vector of bytes.
    ///
    /// See notes on [`Aead::encrypt()`] and [`Aead::decrypt()`] about allowable
    /// message payloads and Associated Additional Data (AAD).
    fn decrypt<'msg, 'aad>(
        &mut self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error>;
}

/// A blanket implementation of the Stateful AEAD interface for Stateless
/// AEAD implementations.
impl<Algo: Aead> AeadMut for Algo {
    type NonceSize = Algo::NonceSize;
    type TagSize = Algo::TagSize;
    type CiphertextOverhead = Algo::CiphertextOverhead;

    /// Encrypt the given plaintext slice, and return the resulting ciphertext
    /// as a vector of bytes.
    fn encrypt<'msg, 'aad>(
        &mut self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error> {
        <Self as Aead>::encrypt(self, nonce, plaintext)
    }

    /// Decrypt the given ciphertext slice, and return the resulting plaintext
    /// as a vector of bytes.
    fn decrypt<'msg, 'aad>(
        &mut self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error> {
        <Self as Aead>::decrypt(self, nonce, ciphertext)
    }
}

/// AEAD payloads are a combination of a message (plaintext or ciphertext)
/// and "additional associated data" (AAD) to be authenticated (in cleartext)
/// along with the message.
///
/// If you don't care about AAD, you can pass a `&[u8]` as the payload to
/// `encrypt`/`decrypt` and it will automatically be coerced to this type.
pub struct Payload<'msg, 'aad> {
    /// Message to be encrypted/decrypted
    pub msg: &'msg [u8],

    /// Optional "additional associated data" to authenticate along with
    /// this message. If AAD is provided at the time the message is encrypted,
    /// the same AAD *MUST* be provided at the time the message is decrypted,
    /// or decryption will fail.
    pub aad: &'aad [u8],
}

impl<'msg, 'aad> From<&'msg [u8]> for Payload<'msg, 'aad> {
    fn from(msg: &'msg [u8]) -> Self {
        Self { msg, aad: b"" }
    }
}
