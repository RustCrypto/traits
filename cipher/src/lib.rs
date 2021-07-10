//! This crate defines a set of traits which describe the functionality of
//! [block ciphers][1] and [stream ciphers][2].
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher
//! [2]: https://en.wikipedia.org/wiki/Stream_cipher

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "rand_core")]
#[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
pub use rand_core;

#[cfg(feature = "dev")]
pub use blobby;

mod block;
#[cfg(feature = "dev")]
mod dev;
pub mod errors;
mod mode;
mod stream;

#[cfg(feature = "mode_wrapper")]
mod mode_wrapper;

pub use crate::{block::*, mode::*, stream::*};
pub use generic_array::{self, typenum::consts};
#[cfg(feature = "mode_wrapper")]
pub use mode_wrapper::{BlockModeDecryptWrapper, BlockModeEncryptWrapper};

use crate::errors::InvalidLength;
use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};
#[cfg(feature = "rand_core")]
use rand_core::{CryptoRng, RngCore};

// note: ideally the  following traits would be defined in the `crypto-common` crate,
// but it would make impossible the generic impls over `T: FromBlockCipher(Nonce)`
// in the `block` module, see the following link for proposal to change it:
// https://internals.rust-lang.org/t/14125

/// Trait for types which can be created from key and nonce.
pub trait FromKeyNonce: Sized {
    /// Key size in bytes.
    type KeySize: ArrayLength<u8>;

    /// Nonce size in bytes.
    type NonceSize: ArrayLength<u8>;

    /// Create new value from fixed length key and nonce.
    fn new(
        key: &GenericArray<u8, Self::KeySize>,
        nonce: &GenericArray<u8, Self::NonceSize>,
    ) -> Self;

    /// Create new value from variable length key and nonce.
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

    /// Generate a random key using the provided [`CryptoRng`].
    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    #[inline]
    fn generate_key(mut rng: impl CryptoRng + RngCore) -> GenericArray<u8, Self::KeySize> {
        let mut key = GenericArray::<u8, Self::KeySize>::default();
        rng.fill_bytes(&mut key);
        key
    }

    /// Generate a random nonce using the provided [`CryptoRng`].
    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    #[inline]
    fn generate_nonce(mut rng: impl CryptoRng + RngCore) -> GenericArray<u8, Self::NonceSize> {
        let mut nonce = GenericArray::<u8, Self::NonceSize>::default();
        rng.fill_bytes(&mut nonce);
        nonce
    }

    /// Generate random key and nonce using the provided [`CryptoRng`].
    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    #[inline]
    fn generate_key_nonce(
        mut rng: impl CryptoRng + RngCore,
    ) -> (
        GenericArray<u8, Self::KeySize>,
        GenericArray<u8, Self::NonceSize>,
    ) {
        (Self::generate_key(&mut rng), Self::generate_nonce(&mut rng))
    }
}

/// Trait for types which can be created from key.
pub trait FromKey: Sized {
    /// Key size in bytes.
    type KeySize: ArrayLength<u8>;

    /// Create new value from fixed size key.
    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self;

    /// Create new value from variable size key.
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        if key.len() != Self::KeySize::to_usize() {
            Err(InvalidLength)
        } else {
            Ok(Self::new(GenericArray::from_slice(key)))
        }
    }

    /// Generate a random key using the provided [`CryptoRng`].
    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    #[inline]
    fn generate_key(mut rng: impl CryptoRng + RngCore) -> GenericArray<u8, Self::KeySize> {
        let mut key = GenericArray::<u8, Self::KeySize>::default();
        rng.fill_bytes(&mut key);
        key
    }
}
