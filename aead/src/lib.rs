//! A set of traits designed to support authenticated encryption.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(all(feature = "alloc", not(has_extern_crate_alloc)), feature(alloc))]

#![cfg(feature = "std")]
extern crate core;
extern crate generic_array;

use generic_array::typenum::Unsigned;
use generic_array::{GenericArray, ArrayLength};
use core::marker::PhantomData;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Error;

/// A trait which can support a stateful, RFC5116 authenticated encryption
/// scheme with a fixed-size nonce.
pub trait Aead {
    /// The key size in a new method.
    type KeySize: ArrayLength<u8> + Unsigned;
    /// The length of a nonce.
    type NonceSize: ArrayLength<u8> + Unsigned;
    /// The maximum length of the nonce.
    type TagSize: ArrayLength<u8> + Unsigned;
    /// The amount of suffix padding, in bytes, which needs to be appended to
    /// a plaintext to accommodate this cipher's output.
    type CiphertextOverhead: ArrayLength<u8> + Unsigned;

    /// Construct a new stateful instance for the given key.
    fn for_key(key: GenericArray<u8, Self::KeySize>) -> Self;

    /// Perform an in-place encryption of the given plaintext, which is built
    /// from the first plaintext_used bytes of the pre-populated plaintext
    /// buffer.
    ///
    /// Implementers are responsible for shifting any existing contents of the
    /// plaintext, if necessary, and returning a slice trimmed to the
    /// algorithm-specific ciphertext.
    fn encrypt<'in_out, AdItem: AsRef<[u8]>, AdIter: Iterator<Item = AdItem>>(
        &mut self,
        additional_data: AdIter,
        nonce: &mut GenericArray<u8, Self::NonceSize>,
        plaintext: &'in_out mut [u8],
        plaintext_used: usize,
    ) -> Result<&'in_out mut [u8], Error>;

    /// Perform an in-place decryption of the given ciphertext, as constructed
    /// by the algorithm's `encrypt()` method, and returns a slice of the
    /// plaintext.
    fn decrypt<'in_out, AdItem: AsRef<[u8]>, AdIter: Iterator<Item = AdItem>>(
        &mut self,
        additional_data: AdIter,
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: &'in_out mut [u8],
    ) -> Result<&'in_out mut [u8], Error>;
}

/// A trait which can support a stateless RFC5116 authenticated encryption
/// scheme. This is the standard RFC algorithm.
pub trait StatelessAead {
    /// The key size in a new method.
    type KeySize: ArrayLength<u8> + Unsigned;
    /// The length of a nonce.
    type NonceSize: ArrayLength<u8> + Unsigned;
    /// The maximum length of the nonce.
    type TagSize: ArrayLength<u8> + Unsigned;
    /// The amount of suffix padding, in bytes, which needs to be
    /// appended to a plaintext to accomodate this cipher's output.
    type CiphertextOverhead: ArrayLength<u8> + Unsigned;

    /// Encrypts the given plaintext into a new ciphertext object and the nonce
    fn encrypt<'in_out, AdItem: AsRef<[u8]>, AdIter: Iterator<Item = AdItem>>(
        key: &GenericArray<u8, Self::KeySize>,
        additional_data: AdIter,
        nonce: &mut GenericArray<u8, Self::NonceSize>,
        plaintext: &'in_out mut [u8],
        plaintext_used: usize,
    ) -> Result<&'in_out mut [u8], Error>;

    /// Authenticates the ciphertext, nonce, and additional data, then
    /// decrypts the ciphertext contents into plaintext.
    fn decrypt<'in_out, AdItem: AsRef<[u8]>, AdIter: Iterator<Item = AdItem>>(
        key: &GenericArray<u8, Self::KeySize>,
        additional_data: AdIter,
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: &'in_out mut [u8],
    ) -> Result<&'in_out mut [u8], Error>;
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

    fn for_key(key: GenericArray<u8, Self::KeySize>) -> Self {
        Self {
            key,
            _aead: PhantomData::default(),
        }
    }

    fn encrypt<'in_out, AdItem: AsRef<[u8]>, AdIter: Iterator<Item = AdItem>>(
        &mut self,
        additional_data: AdIter,
        nonce: &mut GenericArray<u8, Self::NonceSize>,
        plaintext: &'in_out mut [u8],
        plaintext_used: usize,
    ) -> Result<&'in_out mut [u8], Error> {
        Algo::encrypt(&self.key, additional_data, nonce, plaintext, plaintext_used)
    }

    fn decrypt<'in_out, AdItem: AsRef<[u8]>, AdIter: Iterator<Item = AdItem>>(
        &mut self,
        additional_data: AdIter,
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: &'in_out mut [u8],
    ) -> Result<&'in_out mut [u8], Error> {
        Algo::decrypt(&self.key, additional_data, nonce, ciphertext)
    }
}

#[cfg(any(feature = "alloc", all(feature = "std", has_extern_crate_alloc)))]
extern crate alloc;

#[cfg(any(feature = "alloc", all(feature = "std", has_extern_crate_alloc)))]
use alloc::vec::Vec;
#[cfg(all(feature = "std", not(any(feature = "alloc", has_extern_crate_alloc))))]
use std::vec::Vec;

#[cfg(any(feature = "alloc", feature = "std"))]
/// Users who wish to use vectors instead of mutable byte slices should
/// utilize this API.
pub trait AeadVec<Algo: Aead> {
    fn encrypt_vec<AdItem: AsRef<[u8]>, AdIter: Iterator<Item = AdItem>>(
        &mut self,
        additional_data: AdIter,
        nonce: &mut GenericArray<u8, Algo::NonceSize>,
        plaintext: Vec<u8>
    ) -> Result<Vec<u8>, Error>;

    fn decrypt_vec<AdItem: AsRef <[u8]>, AdIter: Iterator<Item = AdItem>>(
        &mut self,
        additional_data: AdIter,
        nonce: &GenericArray<u8, Algo::NonceSize>,
        ciphertext: Vec<u8>
    ) -> Result<Vec<u8>, Error>;
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// When built with the `alloc` or `std` features, AEAD algorithms can operate
/// on vectors instead of simply byte slices. This functionality is
/// automatically provided for all algorithms.
impl<Algo: Aead> AeadVec<Algo> for Algo {
    fn encrypt_vec<AdItem: AsRef<[u8]>, AdIter: Iterator<Item = AdItem>>(
        &mut self,
        additional_data: AdIter,
        nonce: &mut GenericArray<u8, Algo::NonceSize>,
        plaintext: Vec<u8>
    ) -> Result<Vec<u8>, Error> {
        let used = plaintext.len();
        let required_len = used + Algo::CiphertextOverhead::to_usize();
        let mut retval = plaintext;
        retval.resize(required_len, 0);

        let truncate_to = {
            self.encrypt(additional_data, nonce, retval.as_mut_slice(), used)?.len()
        };
        retval.truncate(truncate_to);

        Ok(retval)
    }

    fn decrypt_vec<AdItem: AsRef<[u8]>, AdIter: Iterator<Item = AdItem>>(
        &mut self,
        additional_data: AdIter,
        nonce: &GenericArray<u8, Algo::NonceSize>,
        ciphertext: Vec<u8>
    ) -> Result<Vec<u8>, Error> {
        let mut retval = ciphertext;
        Ok(Vec::from(self.decrypt(additional_data, nonce, retval.as_mut_slice())?))
    }
}


#[cfg(any(feature = "alloc", feature = "std"))]
pub trait StatelessAeadVec<Algo: StatelessAead> {
    fn encrypt_vec<AdItem: AsRef<[u8]>, AdIter: Iterator<Item = AdItem>>(
        key: &GenericArray<u8, Algo::KeySize>,
        additional_data: AdIter,
        nonce: &mut GenericArray<u8, Algo::NonceSize>,
        plaintext: Vec<u8>
    ) -> Result<Vec<u8>, Error>;

    fn decrypt_vec<AdItem: AsRef <[u8]>, AdIter: Iterator<Item = AdItem>>(
        key: &GenericArray<u8, Algo::KeySize>,
        additional_data: AdIter,
        nonce: &GenericArray<u8, Algo::NonceSize>,
        ciphertext: Vec<u8>
    ) -> Result<Vec<u8>, Error>;
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// When built with the `alloc` or `std` features, stateless AEAD algorithms
/// can operate on vectors instead of simply byte slices.
impl<Algo: StatelessAead> StatelessAeadVec<Algo> for Algo {
    fn encrypt_vec<AdItem: AsRef<[u8]>, AdIter: Iterator<Item = AdItem>>(
        key: &GenericArray<u8, Algo::KeySize>,
        additional_data: AdIter,
        nonce: &mut GenericArray<u8, Algo::NonceSize>,
        plaintext: Vec<u8>
    ) -> Result<Vec<u8>, Error> {
        let used = plaintext.len();
        let required_len = used + Algo::CiphertextOverhead::to_usize();
        let mut retval = plaintext;
        retval.resize(required_len, 0);

        let truncate_to = {
            Algo::encrypt(key, additional_data, nonce, retval.as_mut_slice(), used)?.len()
        };
        retval.truncate(truncate_to);

        Ok(retval)
    }

    fn decrypt_vec<AdItem: AsRef<[u8]>, AdIter: Iterator<Item = AdItem>>(
        key: &GenericArray<u8, Algo::KeySize>,
        additional_data: AdIter,
        nonce: &GenericArray<u8, Algo::NonceSize>,
        ciphertext: Vec<u8>
    ) -> Result<Vec<u8>, Error> {
        let mut retval = ciphertext;
        Ok(Vec::from(Algo::decrypt(key, additional_data, nonce, retval.as_mut_slice())?))
    }
}
