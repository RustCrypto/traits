//! Common cryptographic traits.

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

use generic_array::{ArrayLength, GenericArray};

#[cfg(feature = "core-api")]
#[cfg_attr(docsrs, doc(cfg(feature = "core-api")))]
pub use block_buffer;

mod init;
pub use init::{InnerInit, InnerIvInit, KeyInit, KeyIvInit};

#[cfg(feature = "core-api")]
#[cfg_attr(docsrs, doc(cfg(feature = "core-api")))]
pub mod core_api;

/// Types which process data in blocks.
pub trait BlockProcessing {
    /// Size of the block in bytes.
    type BlockSize: ArrayLength<u8> + 'static;
}

/// Block on which a [`BlockProcessing`] operates.
pub type Block<B> = GenericArray<u8, <B as BlockProcessing>::BlockSize>;

impl<Alg: BlockProcessing> BlockProcessing for &Alg {
    type BlockSize = Alg::BlockSize;
}

/// Types which consume data.
pub trait Update {
    /// Update state using the provided data.
    fn update(&mut self, data: &[u8]);
}

/// Trait for types which return fixed-sized result after finalization.
pub trait FixedOutput: Sized {
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
pub trait FixedOutputReset: FixedOutput + Reset {
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
