//! This crate provides trait for Message Authentication Code (MAC) algorithms.

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

#[cfg(feature = "cipher")]
pub use cipher;
#[cfg(feature = "cipher")]
use cipher::{BlockCipher, NewBlockCipher};

#[cfg(feature = "dev")]
#[cfg_attr(docsrs, doc(cfg(feature = "dev")))]
pub mod dev;

#[cfg(feature = "core-api")]
#[cfg_attr(docsrs, doc(cfg(feature = "core-api")))]
pub mod core_api;

pub use crypto_common::{FixedOutput, FixedOutputReset, FromKey, InvalidLength, Reset, Update};
pub use generic_array::{self, typenum::consts};

use core::fmt;
use generic_array::GenericArray;
use subtle::{Choice, ConstantTimeEq};

/// Key for an algorithm that implements [`FromKey`].
pub type Key<M> = GenericArray<u8, <M as FromKey>::KeySize>;

/// Convinience super-trait covering functionality of Message Authentication algorithms.
pub trait Mac: FromKey + Update + FixedOutput {
    /// Obtain the result of a [`Mac`] computation as a [`Output`] and consume
    /// [`Mac`] instance.
    fn finalize(self) -> Output<Self> {
        Output::new(self.finalize_fixed())
    }

    /// Obtain the result of a [`Mac`] computation as a [`Output`] and reset
    /// [`Mac`] instance.
    fn finalize_reset(&mut self) -> Output<Self>
    where
        Self: FixedOutputReset,
    {
        Output::new(self.finalize_fixed_reset())
    }

    /// Check if tag/code value is correct for the processed input.
    fn verify(self, tag: &[u8]) -> Result<(), MacError> {
        let choice = self.finalize().bytes.ct_eq(tag);

        if choice.unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(MacError)
        }
    }
}

impl<T: FromKey + Update + FixedOutput> Mac for T {}

/// [`Output`] is a thin wrapper around bytes array which provides a safe `Eq`
/// implementation that runs in a fixed time.
#[derive(Clone)]
pub struct Output<M: Mac> {
    bytes: GenericArray<u8, M::OutputSize>,
}

impl<M: Mac> Output<M> {
    /// Create a new MAC [`Output`].
    pub fn new(bytes: GenericArray<u8, M::OutputSize>) -> Output<M> {
        Output { bytes }
    }

    /// Get the MAC tag/code value as a byte array.
    ///
    /// Be very careful using this method, since incorrect use of the tag value
    /// may permit timing attacks which defeat the security provided by the
    /// [`Mac`] trait.
    pub fn into_bytes(self) -> GenericArray<u8, M::OutputSize> {
        self.bytes
    }
}

impl<M: Mac> ConstantTimeEq for Output<M> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl<M: Mac> PartialEq for Output<M> {
    fn eq(&self, x: &Output<M>) -> bool {
        self.ct_eq(x).unwrap_u8() == 1
    }
}

impl<M: Mac> Eq for Output<M> {}

/// Error type for signaling failed MAC verification
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub struct MacError;

impl fmt::Display for MacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("failed MAC verification")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MacError {}
