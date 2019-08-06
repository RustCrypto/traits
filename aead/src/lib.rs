//! A set of traits designed to support authenticated encryption.

#![no_std]

use generic_array::typenum::Unsigned;
use generic_array::{GenericArray, ArrayLength};
use core::marker::PhantomData;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Error;

/// A trait which can support a stateful, RFC5116 authenticated encryption
/// scheme.
pub trait Aead: Sized {
    /// The key size in a new method.
    type KeyLength: ArrayLength<u8> + Unsigned;
    /// The maximum length a plaintext can be.
    type PlaintextMax: ArrayLength<u8> + Unsigned;
    /// The maximum length a ciphertext can be.
    type CiphertextMax: ArrayLength<u8> + Unsigned;
    /// The maximum length of the associated data.
    type AssociatedDataMax: ArrayLength<u8> + Unsigned;
    /// The minimum length of the nonce.
    type NonceMin: ArrayLength<u8> + Unsigned;
    /// The maximum length of the nonce.
    type NonceMax: ArrayLength<u8> + Unsigned;

    /// An actual type for the nonce
    type Nonce;

    /// Retrieve the size of the buffer required for plaintext of a given size.
    fn ciphertext_len(&self, plaintext_used: usize) -> usize;

    /// Construct a new stateful instance for the given key.
    fn for_key(key: GenericArray<u8, Self::KeyLength>) -> Self;

    /// Perform an in-place encryption of the given plaintext, which is built
    /// from the first plaintext_used bytes of the pre-populated plaintext
    /// buffer.
    ///
    /// Implementers are responsible for shifting any existing contents of the
    /// plaintext, if necessary, and returning a slice trimmed to the
    /// algorithm-specific ciphertext.
    fn encrypt<'in_out>(
        &mut self,
        additional_data: impl Iterator<Item = impl AsRef<[u8]>>,
        nonce: &mut Self::Nonce,
        plaintext: &'in_out mut [u8],
        plaintext_used: usize,
    ) -> Result<&'in_out mut [u8], Error>;

    /// Perform an in-place decryption of the given ciphertext, as constructed
    /// by the algorithm's `encrypt()` method, and returns a slice of the
    /// plaintext.
    fn decrypt<'in_out>(
        &mut self,
        additional_data: impl Iterator<Item =  impl AsRef<[u8]>>,
        nonce: &Self::Nonce,
        ciphertext: &'in_out mut [u8],
    ) -> Result<&'in_out mut [u8], Error>;
}

/// A trait which can support a stateless RFC5116 authenticated encryption
/// scheme. This is the standard RFC algorithm.
pub trait StatelessAead {
    /// The key size in a new method.
    type KeyLength: ArrayLength<u8> + Unsigned;
    /// The maximum length a plaintext can be.
    type PlaintextMax: ArrayLength<u8> + Unsigned;
    /// The maximum length a ciphertext can be.
    type CiphertextMax: ArrayLength<u8> + Unsigned;
    /// The maximum length of the associated data.
    type AssociatedDataMax: ArrayLength<u8> + Unsigned;
    /// The minimum length of the nonce.
    type NonceMin: ArrayLength<u8> + Unsigned;
    /// The maximum length of the nonce.
    type NonceMax: ArrayLength<u8> + Unsigned;

    /// An actual type indicating the nonce
    type Nonce;

    /// Retrieve the size of the buffer required for plaintext of a given size.
    fn ciphertext_len(plaintext_used: usize) -> usize;

    /// Encrypts the given plaintext into a new ciphertext object and the nonce
    fn encrypt<'in_out>(
        key: &GenericArray<u8, Self::KeyLength>,
        additional_data: impl Iterator<Item = impl AsRef<[u8]>>,
        nonce: &mut Self::Nonce,
        plaintext: &'in_out mut [u8],
        plaintext_used: usize,
    ) -> Result<&'in_out mut [u8], Error>;

    /// Authenticates the ciphertext, nonce, and additional data, then
    /// decrypts the ciphertext contents into plaintext.
    fn decrypt<'in_out>(
        key: &GenericArray<u8, Self::KeyLength>,
        additional_data: impl Iterator<Item = impl AsRef<[u8]>>,
        nonce: &Self::Nonce,
        ciphertext: &'in_out mut [u8],
    ) -> Result<&'in_out mut [u8], Error>;
}

/// A wrapper structure to allow using a stateless AEAD from the stateful
/// interface.
pub struct Stateful<Algo: StatelessAead> {
    key: GenericArray<u8, <Self as Aead>::KeyLength>,
    _aead: PhantomData<fn() -> Algo>
}

impl<Algo: StatelessAead> Aead for Stateful<Algo> {
    type KeyLength = Algo::KeyLength;
    type PlaintextMax = Algo::PlaintextMax;
    type CiphertextMax = Algo::CiphertextMax;
    type AssociatedDataMax = Algo::AssociatedDataMax;
    type NonceMin = Algo::NonceMin;
    type NonceMax = Algo::NonceMax;
    type Nonce = Algo::Nonce;

    fn ciphertext_len(&self, plaintext_used: usize) -> usize {
        Algo::ciphertext_len(plaintext_used)
    }

    fn for_key(key: GenericArray<u8, Self::KeyLength>) -> Self {
        Self {
            key,
            _aead: PhantomData::default(),
        }
    }

    fn encrypt<'in_out>(
        &mut self,
        additional_data: impl Iterator<Item = impl AsRef<[u8]>>,
        nonce: &mut Self::Nonce,
        plaintext: &'in_out mut [u8],
        plaintext_used: usize,
    ) -> Result<&'in_out mut [u8], Error> {
        Algo::encrypt(&self.key, additional_data, nonce, plaintext, plaintext_used)
    }

    fn decrypt<'in_out>(
        &mut self,
        additional_data: impl Iterator<Item =  impl AsRef<[u8]>>,
        nonce: &Self::Nonce,
        ciphertext: &'in_out mut [u8],
    ) -> Result<&'in_out mut [u8], Error> {
        Algo::decrypt(&self.key, additional_data, nonce, ciphertext)
    }
}
