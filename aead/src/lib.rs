//! A set of traits designed to support authenticated encryption.

#![no_std]

extern crate alloc;

pub use generic_array;

use alloc::vec::Vec;
use generic_array::{GenericArray, ArrayLength, typenum::Unsigned};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Error;

/// A trait which can be used to create a new RFC5116 authenticated encryption
/// scheme.
pub trait NewAead {
    /// The size of the key array required by this algorithm.
    type KeySize: ArrayLength<u8>;

    /// Construct a new stateful instance for the given key.
    fn new(key: GenericArray<u8, Self::KeySize>) -> Self;
}

/// A trait which can support a stateful, RFC5116 authenticated encryption
/// scheme with a fixed-size nonce.
pub trait Aead {
    /// The length of a nonce.
    type NonceSize: ArrayLength<u8>;
    /// The maximum length of the nonce.
    type TagSize: ArrayLength<u8>;
    /// The upper bound amount of additional space required to support a
    /// ciphertext vs. a plaintext.
    type CiphertextOverhead: ArrayLength<u8> + Unsigned;

    /// Encrypt the given plaintext slice, and return the resulting ciphertext
    /// as a vector of bytes.
    fn encrypt(
        &mut self,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: &[u8]
    ) -> Result<Vec<u8>, Error>;

    /// Decrypt the given ciphertext slice, and return the resulting plaintext
    /// as a vector of bytes.
    fn decrypt(
        &mut self,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: &[u8]
    ) -> Result<Vec<u8>, Error>;
}

/// A trait which can support a stateless RFC5116 authenticated encryption
/// scheme. This is the standard RFC algorithm.
pub trait StatelessAead {
    /// The length of a nonce.
    type NonceSize: ArrayLength<u8>;
    /// The maximum length of the nonce.
    type TagSize: ArrayLength<u8>;
    /// The upper bound amount of additional space required to support a
    /// ciphertext vs. a plaintext.
    type CiphertextOverhead: ArrayLength<u8> + Unsigned;

    /// Encrypt the given plaintext slice, and return the resulting ciphertext
    /// as a vector of bytes.
    fn encrypt(
        &self,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: &[u8]
    ) -> Result<Vec<u8>, Error>;

    /// Decrypt the given ciphertext slice, and return the resulting plaintext
    /// as a vector of bytes.
    fn decrypt(
        &self,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: &[u8]
    ) -> Result<Vec<u8>, Error>;
}

/// A blanket implementation of the Stateful AEAD interface for Stateless
/// AEAD implementations.
impl<Algo: StatelessAead> Aead for Algo {
    type NonceSize = Algo::NonceSize;
    type TagSize = Algo::TagSize;
    type CiphertextOverhead = Algo::CiphertextOverhead;

    /// Encrypt the given plaintext slice, and return the resulting ciphertext
    /// as a vector of bytes.
    fn encrypt(
        &mut self,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: &[u8]
    ) -> Result<Vec<u8>, Error> {
        <Self as StatelessAead>::encrypt(self, additional_data, nonce, plaintext)
    }

    /// Decrypt the given ciphertext slice, and return the resulting plaintext
    /// as a vector of bytes.
    fn decrypt(
        &mut self,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: &[u8]
    ) -> Result<Vec<u8>, Error> {
        <Self as StatelessAead>::decrypt(self, additional_data, nonce, ciphertext)
    }
}
