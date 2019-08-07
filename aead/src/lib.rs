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

use generic_array::typenum::Unsigned;
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

    /// Perform an in-place encryption of the given plaintext, which is built
    /// from the first plaintext_used bytes of the pre-populated plaintext
    /// buffer.
    ///
    /// Implementers are responsible for shifting any existing contents of the
    /// plaintext, if necessary, and returning a slice trimmed to the
    /// algorithm-specific ciphertext.
    fn encrypt<'in_out>(
        &mut self,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: &'in_out mut [u8],
        plaintext_used: usize,
    ) -> Result<&'in_out [u8], Error>;

    /// Perform an in-place decryption of the given ciphertext, as constructed
    /// by the algorithm's `encrypt_vec()` method, and returns a slice
    /// containing the plaintext.
    fn decrypt<'in_out>(
        &mut self,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: &'in_out mut [u8],
    ) -> Result<&'in_out [u8], Error>;

    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Consume a plaintext vector, encrypt it in-place, and return the
    /// resulting ciphertext.
    ///
    /// A default implementation is provided which should be sufficient for
    /// most cases.
    fn encrypt_vec(
        &mut self,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: Vec<u8>
    ) -> Result<Vec<u8>, Error> {
        let used = plaintext.len();
        let required_len = used + Self::CiphertextOverhead::to_usize();
        let mut retval = plaintext;
        retval.resize(required_len, 0);

        let truncate_to = {
            self.encrypt(additional_data, nonce, retval.as_mut_slice(), used)?.len()
        };
        retval.truncate(truncate_to);

        Ok(retval)
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Consume a ciphertext vector, decrypt it in-place, and return a copy in
    /// a new vector.
    ///
    /// A sub-optimal default implementation is provided, but AEAD implementers
    /// are welcome to provide more optimized versions as desired.
    fn decrypt_vec(
        &mut self,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: Vec<u8>
    ) -> Result<Vec<u8>, Error> {
        let mut retval = ciphertext;
        Ok(Vec::from(self.decrypt(additional_data, nonce, retval.as_mut_slice())?))
    }
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

    /// Encrypts the given plaintext into a new ciphertext object and the nonce
    fn encrypt<'in_out>(
        key: &GenericArray<u8, Self::KeySize>,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: &'in_out mut [u8],
        plaintext_used: usize,
    ) -> Result<&'in_out [u8], Error>;

    /// Authenticates the ciphertext, nonce, and additional data, then
    /// decrypts the ciphertext contents into plaintext.
    fn decrypt<'in_out>(
        key: &GenericArray<u8, Self::KeySize>,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: &'in_out mut [u8],
    ) -> Result<&'in_out [u8], Error>;

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn encrypt_vec(
        key: &GenericArray<u8, Self::KeySize>,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: Vec<u8>
    ) -> Result<Vec<u8>, Error> {
        let used = plaintext.len();
        let required_len = used + Self::CiphertextOverhead::to_usize();
        let mut retval = plaintext;
        retval.resize(required_len, 0);

        let truncate_to = {
            Self::encrypt(key, additional_data, nonce, retval.as_mut_slice(), used)?.len()
        };
        retval.truncate(truncate_to);

        Ok(retval)
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    fn decrypt_vec(
        key: &GenericArray<u8, Self::KeySize>,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: Vec<u8>
    ) -> Result<Vec<u8>, Error> {
        let mut retval = ciphertext;
        Ok(Vec::from(Self::decrypt(key, additional_data, nonce, retval.as_mut_slice())?))
    }
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

    fn encrypt<'in_out>(
        &mut self,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: &'in_out mut [u8],
        plaintext_used: usize,
    ) -> Result<&'in_out [u8], Error> {
        Algo::encrypt(&self.key, additional_data, nonce, plaintext, plaintext_used)
    }

    fn decrypt<'in_out>(
        &mut self,
        additional_data: &[u8],
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: &'in_out mut [u8],
    ) -> Result<&'in_out [u8], Error> {
        Algo::decrypt(&self.key, additional_data, nonce, ciphertext)
    }
}
