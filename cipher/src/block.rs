//! Traits used to define functionality of [block ciphers][1].
//!
//! # About block ciphers
//!
//! Block ciphers are keyed, deterministic permutations of a fixed-sized input
//! "block" providing a reversible transformation to/from an encrypted output.
//! They are one of the fundamental structural components of [symmetric cryptography][2].
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher
//! [2]: https://en.wikipedia.org/wiki/Symmetric-key_algorithm

use core::convert::TryInto;
use crypto_common::FromKey;
use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};

/// Key for an algorithm that implements [`FromKey`].
pub type BlockCipherKey<B> = GenericArray<u8, <B as FromKey>::KeySize>;

/// Block on which a [`BlockCipher`] operates.
pub type Block<B> = GenericArray<u8, <B as BlockCipher>::BlockSize>;

/// Block on which a [`BlockCipher`] operates in parallel.
pub type ParBlocks<B> = GenericArray<Block<B>, <B as BlockCipher>::ParBlocks>;

/// Trait which marks a type as being a block cipher.
pub trait BlockCipher {
    /// Size of the block in bytes
    type BlockSize: ArrayLength<u8>;

    /// Number of blocks which can be processed in parallel by
    /// cipher implementation
    type ParBlocks: ArrayLength<Block<Self>>;
}

/// Encrypt-only functionality for block ciphers.
pub trait BlockEncrypt: BlockCipher {
    /// Encrypt block in-place
    fn encrypt_block(&self, block: &mut Block<Self>);

    /// Encrypt several blocks in parallel using instruction level parallelism
    /// if possible.
    ///
    /// If `ParBlocks` equals to 1 it's equivalent to `encrypt_block`.
    #[inline]
    fn encrypt_par_blocks(&self, blocks: &mut ParBlocks<Self>) {
        for block in blocks.iter_mut() {
            self.encrypt_block(block);
        }
    }

    /// Encrypt a slice of blocks, leveraging parallelism when available.
    #[inline]
    fn encrypt_blocks(&self, mut blocks: &mut [Block<Self>]) {
        let pb = Self::ParBlocks::to_usize();

        if pb > 1 {
            let mut iter = blocks.chunks_exact_mut(pb);

            for chunk in &mut iter {
                self.encrypt_par_blocks(chunk.try_into().unwrap())
            }

            blocks = iter.into_remainder();
        }

        for block in blocks {
            self.encrypt_block(block);
        }
    }
}

/// Decrypt-only functionality for block ciphers.
pub trait BlockDecrypt: BlockCipher {
    /// Decrypt block in-place
    fn decrypt_block(&self, block: &mut Block<Self>);

    /// Decrypt several blocks in parallel using instruction level parallelism
    /// if possible.
    ///
    /// If `ParBlocks` equals to 1 it's equivalent to `decrypt_block`.
    #[inline]
    fn decrypt_par_blocks(&self, blocks: &mut ParBlocks<Self>) {
        for block in blocks.iter_mut() {
            self.decrypt_block(block);
        }
    }

    /// Decrypt a slice of blocks, leveraging parallelism when available.
    #[inline]
    fn decrypt_blocks(&self, mut blocks: &mut [Block<Self>]) {
        let pb = Self::ParBlocks::to_usize();

        if pb > 1 {
            let mut iter = blocks.chunks_exact_mut(pb);

            for chunk in &mut iter {
                self.decrypt_par_blocks(chunk.try_into().unwrap())
            }

            blocks = iter.into_remainder();
        }

        for block in blocks {
            self.decrypt_block(block);
        }
    }
}

/// Encrypt-only functionality for block ciphers with mutable access to `self`.
///
/// The main use case for this trait is hardware encryption engines which
/// require `&mut self` access to an underlying hardware peripheral.
pub trait BlockEncryptMut: BlockCipher {
    /// Encrypt block in-place
    fn encrypt_block_mut(&mut self, block: &mut Block<Self>);
}

/// Decrypt-only functionality for block ciphers with mutable access to `self`.
///
/// The main use case for this trait is hardware encryption engines which
/// require `&mut self` access to an underlying hardware peripheral.
pub trait BlockDecryptMut: BlockCipher {
    /// Decrypt block in-place
    fn decrypt_block_mut(&mut self, block: &mut Block<Self>);
}

impl<Alg: BlockEncrypt> BlockEncryptMut for Alg {
    fn encrypt_block_mut(&mut self, block: &mut Block<Self>) {
        self.encrypt_block(block);
    }
}

impl<Alg: BlockDecrypt> BlockDecryptMut for Alg {
    fn decrypt_block_mut(&mut self, block: &mut Block<Self>) {
        self.decrypt_block(block);
    }
}

// Impls of block cipher traits for reference types

impl<Alg: BlockCipher> BlockCipher for &Alg {
    type BlockSize = Alg::BlockSize;
    type ParBlocks = Alg::ParBlocks;
}

impl<Alg: BlockEncrypt> BlockEncrypt for &Alg {
    #[inline]
    fn encrypt_block(&self, block: &mut Block<Self>) {
        Alg::encrypt_block(self, block);
    }

    #[inline]
    fn encrypt_par_blocks(&self, blocks: &mut ParBlocks<Self>) {
        Alg::encrypt_par_blocks(self, blocks);
    }

    #[inline]
    fn encrypt_blocks(&self, blocks: &mut [Block<Self>]) {
        Alg::encrypt_blocks(self, blocks);
    }
}

impl<Alg: BlockDecrypt> BlockDecrypt for &Alg {
    #[inline]
    fn decrypt_block(&self, block: &mut Block<Self>) {
        Alg::decrypt_block(self, block);
    }

    #[inline]
    fn decrypt_par_blocks(&self, blocks: &mut ParBlocks<Self>) {
        Alg::decrypt_par_blocks(self, blocks);
    }

    #[inline]
    fn decrypt_blocks(&self, blocks: &mut [Block<Self>]) {
        Alg::decrypt_blocks(self, blocks);
    }
}

/// Trait for types which can be initialized from a block cipher and nonce.
pub trait FromBlockCipherNonce {
    /// Block cipher
    type BlockCipher: BlockCipher;
    /// Nonce size in bytes
    type NonceSize: ArrayLength<u8>;

    /// Instantiate a stream cipher from a block cipher
    fn from_block_cipher_nonce(
        cipher: Self::BlockCipher,
        nonce: &GenericArray<u8, Self::NonceSize>,
    ) -> Self;
}

/// Implement [`FromKeyNonce`][crate::FromKeyNonce] for a type which implements [`FromBlockCipherNonce`].
#[macro_export]
macro_rules! impl_from_key_nonce {
    ($name:ty) => {
        impl<C: FromKey> cipher::FromKeyNonce for $name {
            type KeySize = C::KeySize;
            type NonceSize = <Self as FromBlockCipherNonce>::NonceSize;

            fn new(
                key: &GenericArray<u8, Self::KeySize>,
                nonce: &GenericArray<u8, Self::NonceSize>,
            ) -> Self {
                Self::from_block_cipher_nonce(C::new(key), nonce)
            }

            fn new_from_slices(
                key: &[u8],
                nonce: &[u8],
            ) -> Result<Self, cipher::errors::InvalidLength> {
                use cipher::errors::InvalidLength;
                if nonce.len() != Self::NonceSize::USIZE {
                    Err(InvalidLength)
                } else {
                    C::new_from_slice(key)
                        .map_err(|_| InvalidLength)
                        .map(|cipher| {
                            let nonce = GenericArray::from_slice(nonce);
                            Self::from_block_cipher_nonce(cipher, nonce)
                        })
                }
            }
        }
    };
}

/// Implement [`FromKey`] for a type which implements [`From<C>`][From],
/// where `C` implements [`FromKey`].
#[macro_export]
macro_rules! impl_from_key {
    ($name:ty) => {
        impl<C: FromKey> cipher::FromKey for $name
        where
            Self: From<C>,
        {
            type KeySize = C::KeySize;

            fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
                C::new(key).into()
            }

            fn new_from_slice(key: &[u8]) -> Result<Self, cipher::errors::InvalidLength> {
                C::new_from_slice(key)
                    .map_err(|_| cipher::errors::InvalidLength)
                    .map(|cipher| cipher.into())
            }
        }
    };
}
