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
mod fixed;
mod variable;
mod xof;

pub use crate::digest::{Digest, Output};
pub use crate::errors::InvalidOutputSize;
pub use crate::fixed::{FixedOutput, FixedOutputDirty};
pub use crate::variable::{VariableOutput, VariableOutputDirty};
pub use crate::xof::{ExtendableOutput, ExtendableOutputDirty, XofReader};
pub use generic_array::{self, typenum::consts};

#[cfg(feature = "alloc")]
pub use dyn_digest::DynDigest;

use generic_array::ArrayLength;

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
