//! This crate provides traits which describe functionality of cryptographic hash
//! functions.
//!
//! Traits in this repository are organized into high-level convenience traits,
//! mid-level traits which expose more fine-grained functionality, and
//! low-level traits intended to only be used by algorithm implementations:
//!
//! - **High-level convenience traits**: [`Digest`], [`DynDigest`]. They are wrappers
//!   around lower-level traits for most common hash-function use-cases.
//! - **Mid-level traits**: [`Update`], [`FixedOutput`], [`ExtendableOutput`], [`Reset`].
//!   These traits atomically describe available functionality of hash function
//!   implementations.
//! - **Low-level traits**: [`UpdateCore`], [`FixedOutputCore`],
//!   [`ExtendableOutputCore`]. These traits operate at a block-level and do not
//!   contain any built-in buffering. They are intended to be implemented
//!   by low-level algorithm providers only and simplify the amount of work
//!   implementers need to do and therefore usually shouldn't be used in
//!   application-level code.
//!
//! Additionally hash functions implement traits from the standard library:
//! [`Default`], [`Clone`], [`Write`][std::io::Write]. The latter is
//! feature-gated behind `std` feature, which is usually enabled by default
//! by hash implementation crates.
//!
//! The [`Digest`] trait is the most commonly used trait.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

#[cfg(feature = "dev")]
#[cfg_attr(docsrs, doc(cfg(feature = "dev")))]
pub mod dev;

#[cfg(feature = "core-api")]
mod core_api;
mod digest;
#[cfg(feature = "alloc")]
mod dyn_digest;

#[cfg(feature = "core-api")]
pub use crate::core_api::{CoreWrapper, ExtendableOutputCore, FixedOutputCore, UpdateCore};
pub use crate::digest::{Digest, Output};
#[cfg(feature = "core-api")]
pub use block_buffer;
#[cfg(feature = "alloc")]
pub use dyn_digest::{DynDigest, InvalidBufferLength};
pub use generic_array::{self, typenum::consts, ArrayLength, GenericArray};

/// Trait for updating hasher state with input data.
pub trait Update {
    /// Update the hasher state using the provided data.
    fn update(&mut self, data: &[u8]);
}

/// Trait for resetting hasher instances
pub trait Reset {
    /// Reset hasher instance to its initial state.
    fn reset(&mut self);
}

/// Trait for returning digest result with the fixed size
pub trait FixedOutput {
    /// Output size for fixed output digest
    type OutputSize: ArrayLength<u8>;

    /// Write result into provided array and consume the hasher instance.
    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>)
    where
        Self: Sized;

    /// Write result into provided array and reset the hasher instance.
    fn finalize_into_reset(&mut self, out: &mut GenericArray<u8, Self::OutputSize>);

    /// Retrieve result and consume the hasher instance.
    #[inline]
    fn finalize_fixed(self) -> GenericArray<u8, Self::OutputSize>
    where
        Self: Sized,
    {
        let mut out = Default::default();
        self.finalize_into(&mut out);
        out
    }

    /// Retrieve result and reset the hasher instance.
    #[inline]
    fn finalize_fixed_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
        let mut out = Default::default();
        self.finalize_into_reset(&mut out);
        out
    }
}

/// Trait for describing readers which are used to extract extendable output
/// from XOF (extendable-output function) result.
pub trait XofReader {
    /// Read output into the `buffer`. Can be called an unlimited number of times.
    fn read(&mut self, buffer: &mut [u8]);

    /// Read output into a boxed slice of the specified size.
    ///
    /// Can be called an unlimited number of times in combination with `read`.
    ///
    /// `Box<[u8]>` is used instead of `Vec<u8>` to save stack space, since
    /// they have size of 2 and 3 words respectively.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn read_boxed(&mut self, n: usize) -> Box<[u8]> {
        let mut buf = vec![0u8; n].into_boxed_slice();
        self.read(&mut buf);
        buf
    }
}

/// Trait which describes extendable-output functions (XOF).
pub trait ExtendableOutput {
    /// Reader
    type Reader: XofReader;

    /// Retrieve XOF reader and consume hasher instance.
    fn finalize_xof(self) -> Self::Reader
    where
        Self: Sized;

    /// Retrieve XOF reader and reset hasher instance state.
    fn finalize_xof_reset(&mut self) -> Self::Reader;

    /// Retrieve result into a boxed slice of the specified size and consume
    /// the hasher.
    ///
    /// `Box<[u8]>` is used instead of `Vec<u8>` to save stack space, since
    /// they have size of 2 and 3 words respectively.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn finalize_boxed(self, n: usize) -> Box<[u8]>
    where
        Self: Sized,
    {
        let mut buf = vec![0u8; n].into_boxed_slice();
        self.finalize_xof().read(&mut buf);
        buf
    }

    /// Retrieve result into a boxed slice of the specified size and reset
    /// the hasher's state.
    ///
    /// `Box<[u8]>` is used instead of `Vec<u8>` to save stack space, since
    /// they have size of 2 and 3 words respectively.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn finalize_boxed_reset(&mut self, n: usize) -> Box<[u8]> {
        let mut buf = vec![0u8; n].into_boxed_slice();
        self.finalize_xof_reset().read(&mut buf);
        buf
    }
}
