//! This crate defines a set of traits which define functionality of
//! stream ciphers.
//!
//! See [RustCrypto/stream-ciphers](https://github.com/RustCrypto/stream-ciphers)
//! for ciphers implementation.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "dev")]
mod dev;

mod errors;

pub use errors::{InvalidKeyNonceLength, LoopError, OverflowError};
pub use generic_array::{self, typenum::consts};

#[cfg(feature = "block-cipher")]
pub use block_cipher;

#[cfg(feature = "dev")]
pub use blobby;

use core::convert::{TryFrom, TryInto};
use generic_array::typenum::Unsigned;
use generic_array::{ArrayLength, GenericArray};

#[cfg(feature = "block-cipher")]
use block_cipher::{BlockCipher, NewBlockCipher};

/// Key for an algorithm that implements [`NewStreamCipher`].
pub type Key<C> = GenericArray<u8, <C as NewStreamCipher>::KeySize>;

/// Nonce for an algorithm that implements [`NewStreamCipher`].
pub type Nonce<C> = GenericArray<u8, <C as NewStreamCipher>::NonceSize>;

/// Stream cipher creation trait.
///
/// It can be used for creation of synchronous and asynchronous ciphers.
pub trait NewStreamCipher: Sized {
    /// Key size in bytes
    type KeySize: ArrayLength<u8>;

    /// Nonce size in bytes
    type NonceSize: ArrayLength<u8>;

    /// Create new stream cipher instance from variable length key and nonce.
    fn new(key: &Key<Self>, nonce: &Nonce<Self>) -> Self;

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

/// Trait for seekable stream ciphers.
///
/// Methods of this trait are generic over the [`SeekNum`] trait, which is
/// implemented for primitive numeric types, i.e.: `i/u8`, `i/u16`, `i/u32`,
/// `i/u64`, `i/u128`, and `i/usize`.
pub trait SyncStreamCipherSeek {
    /// Try to get current keystream position
    ///
    /// Returns [`LoopError`] if position can not be represented by type `T`
    fn try_current_pos<T: SeekNum>(&self) -> Result<T, OverflowError>;

    /// Try to seek to the given position
    ///
    /// Returns [`LoopError`] if provided position value is bigger than
    /// keystream leangth
    fn try_seek<T: SeekNum>(&mut self, pos: T) -> Result<(), LoopError>;

    /// Get current keystream position
    ///
    /// # Panics
    /// If position can not be represented by type `T`
    fn current_pos<T: SeekNum>(&self) -> T {
        self.try_current_pos().unwrap()
    }

    /// Seek to the given position
    ///
    /// # Panics
    /// If provided position value is bigger than keystream leangth
    fn seek<T: SeekNum>(&mut self, pos: T) {
        self.try_seek(pos).unwrap()
    }
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

impl<C: SyncStreamCipher> SyncStreamCipher for &mut C {
    #[inline]
    fn apply_keystream(&mut self, data: &mut [u8]) {
        C::apply_keystream(self, data);
    }

    #[inline]
    fn try_apply_keystream(&mut self, data: &mut [u8]) -> Result<(), LoopError> {
        C::try_apply_keystream(self, data)
    }
}

/// Trait for initializing a stream cipher from a block cipher
#[cfg(feature = "block-cipher")]
#[cfg_attr(docsrs, doc(cfg(feature = "block-cipher")))]
pub trait FromBlockCipher {
    /// Block cipher
    type BlockCipher: BlockCipher + NewBlockCipher;
    /// Nonce size in bytes
    type NonceSize: ArrayLength<u8>;

    /// Instantiate a stream cipher from a block cipher
    fn from_block_cipher(
        cipher: Self::BlockCipher,
        nonce: &GenericArray<u8, Self::NonceSize>,
    ) -> Self;
}

#[cfg(feature = "block-cipher")]
impl<C> NewStreamCipher for C
where
    C: FromBlockCipher,
{
    type KeySize = <<Self as FromBlockCipher>::BlockCipher as NewBlockCipher>::KeySize;
    type NonceSize = <Self as FromBlockCipher>::NonceSize;

    fn new(key: &Key<Self>, nonce: &Nonce<Self>) -> C {
        C::from_block_cipher(
            <<Self as FromBlockCipher>::BlockCipher as NewBlockCipher>::new(key),
            nonce,
        )
    }

    fn new_var(key: &[u8], nonce: &[u8]) -> Result<Self, InvalidKeyNonceLength> {
        if nonce.len() != Self::NonceSize::USIZE {
            Err(InvalidKeyNonceLength)
        } else {
            C::BlockCipher::new_varkey(key)
                .map_err(|_| InvalidKeyNonceLength)
                .map(|cipher| {
                    let nonce = GenericArray::from_slice(nonce);
                    Self::from_block_cipher(cipher, nonce)
                })
        }
    }
}

/// Trait implemented for numeric types which can be used with the
/// [`SyncStreamCipherSeek`] trait.
///
/// This trait is implemented for primitive numeric types, i.e. `i/u8`,
/// `i/u16`, `i/u32`, `i/u64`, `i/u128`, and `i/usize`. It is not intended
/// to be implemented in third-party crates.
#[rustfmt::skip]
pub trait SeekNum:
    Sized
    + TryInto<u8> + TryFrom<u8> + TryInto<i8> + TryFrom<i8>
    + TryInto<u16> + TryFrom<u16> + TryInto<i16> + TryFrom<i16>
    + TryInto<u32> + TryFrom<u32> + TryInto<i32> + TryFrom<i32>
    + TryInto<u64> + TryFrom<u64> + TryInto<i64> + TryFrom<i64>
    + TryInto<u128> + TryFrom<u128> + TryInto<i128> + TryFrom<i128>
    + TryInto<usize> + TryFrom<usize> + TryInto<isize> + TryFrom<isize>
{
    /// Try to get position for block number `block`, byte position inside
    /// block `byte`, and block size `bs`.
    fn from_block_byte<T: SeekNum>(block: T, byte: u8, bs: u8) -> Result<Self, OverflowError>;

    /// Try to get block number and bytes position for given block size `bs`.
    fn to_block_byte<T: SeekNum>(self, bs: u8) -> Result<(T, u8), OverflowError>;
}

macro_rules! impl_seek_num {
    {$($t:ty )*} => {
        $(
            impl SeekNum for $t {
                fn from_block_byte<T: TryInto<Self>>(block: T, byte: u8, bs: u8) -> Result<Self, OverflowError> {
                    debug_assert!(byte < bs);
                    let block = block.try_into().map_err(|_| OverflowError)?;
                    let pos = block.checked_mul(bs as Self).ok_or(OverflowError)? + (byte as Self);
                    Ok(pos)
                }

                fn to_block_byte<T: TryFrom<Self>>(self, bs: u8) -> Result<(T, u8), OverflowError> {
                    let bs = bs as Self;
                    let byte = self % bs;
                    let block = T::try_from(self/bs).map_err(|_| OverflowError)?;
                    Ok((block, byte as u8))
                }
            }
        )*
    };
}

impl_seek_num! { u8 i8 u16 i16 u32 i32 u64 i64 u128 i128 isize usize }
