//! A set of traits designed to support authenticated encryption.

#![cfg_attr(not(feature = "std"), no_std)]

#![cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate core;
extern crate generic_array;

#[cfg(any(feature = "alloc", all(feature = "std", has_extern_crate_alloc)))]
use alloc::vec::Vec;
#[cfg(all(feature = "std", not(any(feature = "alloc", has_extern_crate_alloc))))]
use std::vec::Vec;

use generic_array::{GenericArray, ArrayLength};
use generic_array::typenum::Unsigned;

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

    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Encrypt the given plaintext and return the ciphertext into a vector.
    fn encrypt_to_vec(
        &mut self,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: &[u8]
    ) -> Result<Vec<u8>, Error> {
        let mut pt_vec = Vec::with_capacity(plaintext.len() + Self::CiphertextOverhead::to_usize());
        pt_vec.extend(plaintext);
        self.encrypt_vec(additional_data, nonce, pt_vec)
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Decrypt the given ciphertext, and return the plaintext as a vector of
    /// bytes.
    fn decrypt_to_vec(
        &mut self,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: &[u8]
    ) -> Result<Vec<u8>, Error> {
        self.decrypt_vec(additional_data, nonce, Vec::from(ciphertext))
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Consume a plaintext vector, encrypt it, and return the resulting
    /// ciphertext as a vector.
    fn encrypt_vec(
        &mut self,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: Vec<u8>
    ) -> Result<Vec<u8>, Error>;

    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Consume a ciphertext vector, decrypt it, and return the resulting
    /// plaintext as a vector of bytes.
    fn decrypt_vec(
        &mut self,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: Vec<u8>
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

    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Encrypt the given plaintext slice, and return the resulting ciphertext
    /// as a vector of bytes.
    fn encrypt_to_vec(&self,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: &[u8]
    ) -> Result<Vec<u8>, Error> {
        let mut pt_vec = Vec::with_capacity(plaintext.len() + Self::CiphertextOverhead::to_usize());
        pt_vec.extend(plaintext);
        self.encrypt_vec(additional_data, nonce, pt_vec)
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Decrypt the given ciphertext, and return the resulting plaintext as a
    /// vector of bytes.
    fn decrypt_to_vec(&self,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: &[u8]
    ) -> Result<Vec<u8>, Error> {
        self.decrypt_vec(additional_data, nonce, Vec::from(ciphertext))
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Consume a plaintext vector, encrypt it, and return the resulting
    /// ciphertext as a vector.
    fn encrypt_vec(
        &self,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: Vec<u8>
    ) -> Result<Vec<u8>, Error>;

    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Consume a ciphertext vector, decrypt it, and return the resulting
    /// plaintext as a vector of bytes.
    fn decrypt_vec(
        &self,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: Vec<u8>
    ) -> Result<Vec<u8>, Error>;
}

/// A blanket implementation of the Stateful AEAD interface for Stateless
/// AEAD implementations.
impl<Algo: StatelessAead> Aead for Algo {
    type NonceSize = Algo::NonceSize;
    type TagSize = Algo::TagSize;
    type CiphertextOverhead = Algo::CiphertextOverhead;

    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Consume a plaintext vector, encrypt it, and return the resulting
    /// ciphertext as a vector.
    fn encrypt_to_vec(
        &mut self,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: &[u8]
    ) -> Result<Vec<u8>, Error> {
        <Self as StatelessAead>::encrypt_to_vec(self, additional_data, nonce, plaintext)
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Consume a ciphertext vector, decrypt it, and return the resulting
    /// plaintext as a vector of bytes.
    fn decrypt_to_vec(
        &mut self,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: &[u8]
    ) -> Result<Vec<u8>, Error> {
        <Self as StatelessAead>::decrypt_to_vec(self, additional_data, nonce, ciphertext)
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Consume a plaintext vector, encrypt it, and return the resulting
    /// ciphertext as a vector.
    fn encrypt_vec(
        &mut self,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: Vec<u8>
    ) -> Result<Vec<u8>, Error> {
        <Self as StatelessAead>::encrypt_vec(self, additional_data, nonce, plaintext)
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Consume a ciphertext vector, decrypt it, and return the resulting
    /// plaintext as a vector of bytes.
    fn decrypt_vec(
        &mut self,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: Vec<u8>
    ) -> Result<Vec<u8>, Error> {
        <Self as StatelessAead>::decrypt_vec(self, additional_data, nonce, ciphertext)
    }
}
