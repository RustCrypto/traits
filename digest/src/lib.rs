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
use alloc::boxed::Box;

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

    /// Write result into provided array and consume the hasher instance.
    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>);

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

/// Trait for fixed-output digest implementations to use to retrieve the
/// hash output.
///
/// Usage of this trait in user code is discouraged. Instead use the
/// [`FixedOutput::finalize_fixed`] or [`FixedOutput::finalize_fixed_reset`]
/// methods.
///
/// Types which impl this trait along with [`Reset`] will receive a blanket
/// impl of [`FixedOutput`].
pub trait FixedOutputDirty {
    /// Output size for fixed output digest
    type OutputSize: ArrayLength<u8>;

    /// Retrieve result into provided buffer and leave hasher in a dirty state.
    ///
    /// Implementations should panic if this is called twice without resetting.
    fn finalize_into_dirty(&mut self, out: &mut GenericArray<u8, Self::OutputSize>);
}

impl<D: FixedOutputDirty + Reset> FixedOutput for D {
    type OutputSize = D::OutputSize;

    #[inline]
    fn finalize_into(mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
        self.finalize_into_dirty(out);
    }

    #[inline]
    fn finalize_into_reset(&mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
        self.finalize_into_dirty(out);
        self.reset();
    }
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

    /// Retrieve result into a boxed slice and consume hasher.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn finalize_box(self) -> Box<[u8]> {
        let n = self.output_size();
        let mut buf = vec![0u8; n].into_boxed_slice();
        self.finalize_variable(|res| buf.copy_from_slice(res));
        buf
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
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn read_box(&mut self, n: usize) -> Box<[u8]> {
        let mut buf = vec![0u8; n].into_boxed_slice();
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

    /// Retrieve result into a boxed slice of the specified size.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn finalize_box(self, n: usize) -> Box<[u8]> {
        let mut buf = vec![0u8; n].into_boxed_slice();
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
