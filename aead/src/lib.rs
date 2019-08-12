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
use core::marker::PhantomData;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Error;

/// A trait which can support a stateful, RFC5116 authenticated encryption
/// scheme with a fixed-size nonce.
pub trait Aead {
    /// The key size in a new method.
    type KeySize: ArrayLength<u8>;
    /// The length of a nonce.
    type NonceSize: ArrayLength<u8>;
    /// The maximum length of the nonce.
    type TagSize: ArrayLength<u8>;
    /// The amount of suffix padding, in bytes, which needs to be appended to
    /// a plaintext to accommodate this cipher's output.
    type CiphertextOverhead: ArrayLength<u8>;

    /// Construct a new stateful instance for the given key.
    fn new(key: GenericArray<u8, Self::KeySize>) -> Self;

    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Consume a plaintext vector, encrypt it in-place, and return the
    /// resulting ciphertext.
    fn encrypt_vec(
        &mut self,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: Vec<u8>
    ) -> Result<Vec<u8>, Error>;

    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Consume a ciphertext vector, decrypt it in-place, and return a copy in
    /// a new vector.
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
    /// The key size in a new method.
    type KeySize: ArrayLength<u8>;
    /// The length of a nonce.
    type NonceSize: ArrayLength<u8>;
    /// The maximum length of the nonce.
    type TagSize: ArrayLength<u8>;
    /// The amount of suffix padding, in bytes, which needs to be
    /// appended to a plaintext to accomodate this cipher's output.
    type CiphertextOverhead: ArrayLength<u8>;

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn encrypt_vec(
        key: &GenericArray<u8, Self::KeySize>,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: Vec<u8>
    ) -> Result<Vec<u8>, Error>;

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn decrypt_vec(
        key: &GenericArray<u8, Self::KeySize>,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: Vec<u8>
    ) -> Result<Vec<u8>, Error>;
}

/// A wrapper structure to allow use of a stateless AEAD through the stateful
/// interface.
pub struct Stateful<Algo: StatelessAead> {
    key: GenericArray<u8, Algo::KeySize>,
    _aead: PhantomData<fn() -> Algo>
}

impl<Algo: StatelessAead> Aead for Stateful<Algo> {
    type KeySize = Algo::KeySize;
    type NonceSize = Algo::NonceSize;
    type TagSize = Algo::TagSize;
    type CiphertextOverhead = Algo::CiphertextOverhead;

    fn new(key: GenericArray<u8, Self::KeySize>) -> Self {
        Self {
            key,
            _aead: PhantomData::default(),
        }
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Consume a plaintext vector, encrypt it in-place, and return the
    /// resulting ciphertext.
    fn encrypt_vec(
        &mut self,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: Vec<u8>
    ) -> Result<Vec<u8>, Error> {
        Algo::encrypt_vec(&self.key, additional_data, nonce, plaintext)
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Consume a ciphertext vector, decrypt it in-place, and return a copy in
    /// a new vector.
    fn decrypt_vec(
        &mut self,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: Vec<u8>
    ) -> Result<Vec<u8>, Error> {
        Algo::decrypt_vec(&self.key, additional_data, nonce, ciphertext)
    }
}
