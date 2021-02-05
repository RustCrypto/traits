//! Functionality common to block ciphers and stream ciphers

use crate::{
    errors::{BufferError, InvalidLength},
    BlockCipher, NewBlockCipher,
};
use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};

#[cfg(feature = "rand_core")]
use rand_core::{CryptoRng, RngCore};

/// Key for an algorithm that implements [`NewCipher`].
pub type CipherKey<C> = GenericArray<u8, <C as NewCipher>::KeySize>;

/// Nonce for an algorithm that implements [`NewCipher`].
pub type Nonce<C> = GenericArray<u8, <C as NewCipher>::NonceSize>;

/// Cipher creation trait.
///
/// It can be used for creation of block modes, synchronous and asynchronous stream ciphers.
pub trait NewCipher: Sized {
    /// Key size in bytes
    type KeySize: ArrayLength<u8>;

    /// Nonce size in bytes
    type NonceSize: ArrayLength<u8>;

    /// Create new stream cipher instance from key and nonce arrays.
    fn new(key: &CipherKey<Self>, nonce: &Nonce<Self>) -> Self;

    /// Create new stream cipher instance from variable length key and nonce
    /// given as byte slices.
    #[inline]
    fn new_from_slices(key: &[u8], nonce: &[u8]) -> Result<Self, InvalidLength> {
        let kl = Self::KeySize::to_usize();
        let nl = Self::NonceSize::to_usize();
        if key.len() != kl || nonce.len() != nl {
            Err(InvalidLength)
        } else {
            let key = GenericArray::from_slice(key);
            let nonce = GenericArray::from_slice(nonce);
            Ok(Self::new(key, nonce))
        }
    }

    /// Generate a random key for this cipher using the provided [`CryptoRng`].
    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    fn generate_key(mut rng: impl CryptoRng + RngCore) -> CipherKey<Self> {
        let mut key = CipherKey::<Self>::default();
        rng.fill_bytes(&mut key);
        key
    }
}

/// Trait for types which can be initialized from a block cipher and nonce.
pub trait FromBlockCipher {
    /// Block cipher
    type BlockCipher: BlockCipher;
    /// Nonce size in bytes
    type NonceSize: ArrayLength<u8>;

    /// Instantiate a stream cipher from a block cipher
    fn from_block_cipher(
        cipher: Self::BlockCipher,
        nonce: &GenericArray<u8, Self::NonceSize>,
    ) -> Self;
}

impl<C> NewCipher for C
where
    C: FromBlockCipher,
    C::BlockCipher: NewBlockCipher,
{
    type KeySize = <<Self as FromBlockCipher>::BlockCipher as NewBlockCipher>::KeySize;
    type NonceSize = <Self as FromBlockCipher>::NonceSize;

    fn new(key: &CipherKey<Self>, nonce: &Nonce<Self>) -> C {
        C::from_block_cipher(
            <<Self as FromBlockCipher>::BlockCipher as NewBlockCipher>::new(key),
            nonce,
        )
    }

    fn new_from_slices(key: &[u8], nonce: &[u8]) -> Result<Self, InvalidLength> {
        if nonce.len() != Self::NonceSize::USIZE {
            Err(InvalidLength)
        } else {
            C::BlockCipher::new_from_slice(key)
                .map_err(|_| InvalidLength)
                .map(|cipher| {
                    let nonce = GenericArray::from_slice(nonce);
                    Self::from_block_cipher(cipher, nonce)
                })
        }
    }
}

/// Perform an encryption operation using a specific buffer type.
///
/// This gives finer-grained control over the buffer type, which is useful
/// in cases which have special requirements, e.g. alignment, SIMD.
pub trait BufferEncrypt<B> {
    /// Encrypt the provided buffer type in-place
    fn encrypt_buffer(&self, buffer: &mut B) -> Result<(), BufferError>;
}

/// Perform an encryption operation on a mutable cipher instance.
///
/// This gives finer-grained control over the buffer type, which is useful
/// in cases which have special requirements, e.g. alignment, SIMD.
pub trait BufferEncryptMut<B> {
    /// Encrypt the provided buffer type in-place
    fn encrypt_buffer_mut(&mut self, buffer: &mut B) -> Result<(), BufferError>;
}
