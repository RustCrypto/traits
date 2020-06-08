//! This crate provides traits which describe functionality of cryptographic hash
//! functions.
//!
//! Traits in this repository can be separated into two levels:
//! - Low level traits: [`Update`], [`BlockInput`], [`Reset`], [`FixedOutput`],
//! [`VariableOutput`], [`ExtendableOutput`]. These traits atomically describe
//! available functionality of hash function implementations.
//! - Convenience trait: [`Digest`], [`DynDigest`]. They are wrappers around
//! low level traits for most common hash-function use-cases.
//!
//! Additionally hash functions implement traits from `std`: `Default`, `Clone`,
//! `Write`. (the latter depends on enabled-by-default `std` crate feature)
//!
//! The [`Digest`] trait is the most commonly used trait.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "dev")]
#[cfg_attr(docsrs, doc(cfg(feature = "dev")))]
pub mod dev;

mod digest;
mod dyn_digest;
mod errors;

pub use crate::digest::{Digest, Output};
pub use crate::errors::InvalidOutputSize;
pub use generic_array::{self, typenum::consts};

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub use dyn_digest::DynDigest;

use generic_array::{ArrayLength, GenericArray};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Trait for updating digest state with input data.
pub trait Update {
    /// Digest input data.
    ///
    /// This method can be called repeatedly, e.g. for processing streaming
    /// messages.
    fn update(&mut self, data: impl AsRef<[u8]>);

    /// Digest input data in a chained manner.
    fn chain(mut self, data: impl AsRef<[u8]>) -> Self
    where
        Self: Sized,
    {
        self.update(data);
        self
    }
}

/// Trait to indicate that digest function processes data in blocks of size
/// `BlockSize`.
///
/// The main usage of this trait is for implementing HMAC generically.
pub trait BlockInput {
    /// Block size
    type BlockSize: ArrayLength<u8>;
}

/// Trait for returning digest result with the fixed size
pub trait FixedOutput {
    /// Output size for fixed output digest
    type OutputSize: ArrayLength<u8>;

    /// Retrieve result and consume hasher instance.
    fn finalize_fixed(self) -> GenericArray<u8, Self::OutputSize>;
}

/// Trait for returning digest result with the variable size
pub trait VariableOutput: core::marker::Sized {
    /// Create new hasher instance with the given output size.
    ///
    /// It will return `Err(InvalidOutputSize)` in case if hasher can not return
    /// specified output size. It will always return an error if output size
    /// equals to zero.
    fn new(output_size: usize) -> Result<Self, InvalidOutputSize>;

    /// Get output size of the hasher instance provided to the `new` method
    fn output_size(&self) -> usize;

    /// Retrieve result via closure and consume hasher.
    ///
    /// Closure is guaranteed to be called, length of the buffer passed to it
    /// will be equal to `output_size`.
    fn finalize_variable<F: FnOnce(&[u8])>(self, f: F);

    /// Retrieve result into vector and consume hasher.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn finalize_vec(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.output_size());
        self.finalize_variable(|res| buf.extend_from_slice(res));
        buf
    }
}

/// Trait for describing readers which are used to extract extendable output
/// from XOF (extendable-output function) result.
pub trait XofReader {
    /// Read output into the `buffer`. Can be called an unlimited number of times.
    fn read(&mut self, buffer: &mut [u8]);

    /// Read output into a vector of the specified size.
    ///
    /// Can be called an unlimited number of times in combination with `read`.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn read_vec(&mut self, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        self.read(&mut buf);
        buf
    }
}

/// Trait which describes extendable-output functions (XOF).
pub trait ExtendableOutput: core::marker::Sized {
    /// Reader
    type Reader: XofReader;

    /// Retrieve XOF reader and consume hasher instance.
    fn finalize_xof(self) -> Self::Reader;

    /// Retrieve result into vector of specified length.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn finalize_vec(self, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        self.finalize_xof().read(&mut buf);
        buf
    }
}

/// Trait for resetting hash instances
pub trait Reset {
    /// Reset hasher instance to its initial state and return current state.
    fn reset(&mut self);
}

#[macro_export]
/// Implements `std::io::Write` trait for implementer of [`Update`]
macro_rules! impl_write {
    ($hasher:ident) => {
        #[cfg(feature = "std")]
        impl std::io::Write for $hasher {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                Update::update(self, buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
    };
}
