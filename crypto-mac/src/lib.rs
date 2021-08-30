//! This crate provides trait for Message Authentication Code (MAC) algorithms.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_root_url = "https://docs.rs/crypto-mac/0.12.0-pre"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "rand_core")]
#[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
pub use rand_core;

#[cfg(feature = "cipher")]
pub use cipher;

#[cfg(feature = "dev")]
#[cfg_attr(docsrs, doc(cfg(feature = "dev")))]
pub mod dev;

pub mod core_api;

use core::fmt;
pub use crypto_common::{
    subtle::ConstantTimeEq, CtOutput, FixedOutput, FixedOutputReset, InvalidLength, Key, KeyInit,
    Output, Reset, Update,
};
pub use generic_array::{
    self,
    typenum::{consts, Unsigned},
};

/// Convinience super-trait covering functionality of Message Authentication algorithms.
pub trait Mac: KeyInit + Update + FixedOutput {
    /// Obtain the result of a [`Mac`] computation as a [`CtOutput`] and consume
    /// [`Mac`] instance.
    #[inline]
    fn finalize(self) -> CtOutput<Self> {
        CtOutput::new(self.finalize_fixed())
    }

    /// Obtain the result of a [`Mac`] computation as a [`CtOutput`] and reset
    /// [`Mac`] instance.
    #[inline]
    fn finalize_reset(&mut self) -> CtOutput<Self>
    where
        Self: FixedOutputReset,
    {
        CtOutput::new(self.finalize_fixed_reset())
    }

    /// Check if tag/code value is correct for the processed input.
    #[inline]
    fn verify(self, other: &Output<Self>) -> Result<(), Error> {
        if self.finalize() == other.into() {
            Ok(())
        } else {
            Err(Error)
        }
    }

    /// Check if a tag/code truncated from right side (i.e. `tag[..n]`)
    /// is correct for the processed input.
    ///
    /// Returns `Error` if `tag` is empty.
    fn verify_truncated_right(self, tag: &[u8]) -> Result<(), Error> {
        let n = tag.len();
        if n == 0 || n > Self::OutputSize::USIZE {
            return Err(Error);
        }
        let choice = self.finalize_fixed()[..n].ct_eq(tag);

        if choice.unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(Error)
        }
    }

    /// Check if a tag/code truncated from left side (i.e. `tag[n..]`)
    /// is correct for the processed input.
    ///
    /// Returns `Error` if `tag` is not valid or empty.
    fn verify_truncated_left(self, tag: &[u8]) -> Result<(), Error> {
        let n = tag.len();
        if n == 0 || n > Self::OutputSize::USIZE {
            return Err(Error);
        }
        let m = Self::OutputSize::USIZE - n;
        let choice = self.finalize_fixed()[m..].ct_eq(tag);

        if choice.unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(Error)
        }
    }
}

/// Error type for when the [`Output`] of a [`Mac`]
/// is not equal to the expected value.
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub struct Error;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MAC output mismatch")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
