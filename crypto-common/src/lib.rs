//! Common cryptographic traits.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

use core::fmt;
use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};
#[cfg(feature = "rand_core")]
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "core-api")]
#[cfg_attr(docsrs, doc(cfg(feature = "core-api")))]
pub mod core_api;

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

/// Trait for types which consume data.
pub trait Update {
    /// Update state using the provided data.
    fn update(&mut self, data: &[u8]);
}

/// Trait for types which return fixed-sized result after finalization.
pub trait FinalizeFixed: Sized {
    /// Size of result in bytes.
    type OutputSize: ArrayLength<u8>;

    /// Consume value and write result into provided array.
    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>);

    /// Retrieve result and consume the hasher instance.
    #[inline]
    fn finalize_fixed(self) -> GenericArray<u8, Self::OutputSize> {
        let mut out = Default::default();
        self.finalize_into(&mut out);
        out
    }
}

/// Trait for types which return fixed-sized result after finalization and reset
/// values into its initial state.
pub trait FinalizeFixedReset: FinalizeFixed + Reset {
    /// Write result into provided array and reset value to its initial state.
    fn finalize_into_reset(&mut self, out: &mut GenericArray<u8, Self::OutputSize>);

    /// Retrieve result and reset the hasher instance.
    #[inline]
    fn finalize_fixed_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
        let mut out = Default::default();
        self.finalize_into_reset(&mut out);
        out
    }
}

/// Trait for resetting values to initial state.
pub trait Reset {
    /// Reset value to its initial state.
    fn reset(&mut self);
}

/// The error type returned when key and/or nonce used in [`FromKey`]
/// or [`FromKeyNonce`] slice-based methods had an invalid length.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct InvalidLength;

impl fmt::Display for InvalidLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("Invalid Length")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidLength {}
