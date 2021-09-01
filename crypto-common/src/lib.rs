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

use block_buffer::DigestBuffer;
use core::fmt;
use generic_array::{
    typenum::{type_operators::IsLess, U256},
    ArrayLength, GenericArray,
};

pub use block_buffer;
#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
pub use subtle;

mod core_wrapper;
#[cfg(feature = "subtle")]
mod ct_output;
mod init;

pub use core_wrapper::*;
#[cfg(feature = "subtle")]
pub use ct_output::CtOutput;
pub use init::*;

/// Block on which [`BlockUser`] implementors operate.
pub type Block<B> = GenericArray<u8, <B as BlockUser>::BlockSize>;

/// Output array of [`OutputSizeUser`] implementors.
pub type Output<T> = GenericArray<u8, <T as OutputSizeUser>::OutputSize>;

/// Types which process data in blocks.
pub trait BlockUser {
    /// Size of the block in bytes.
    type BlockSize: ArrayLength<u8> + IsLess<U256> + 'static;
}

impl<Alg: BlockUser> BlockUser for &Alg {
    type BlockSize = Alg::BlockSize;
}

/// Types which return data with the given size.
pub trait OutputSizeUser {
    /// Size of the output in bytes.
    type OutputSize: ArrayLength<u8> + 'static;
}

/// Types which consume data with byte granularity.
pub trait Update {
    /// Update state using the provided data.
    fn update(&mut self, data: &[u8]);
}

/// Types which return fixed-sized result after finalization.
pub trait FixedOutput: OutputSizeUser + Sized {
    /// Consume value and write result into provided array.
    fn finalize_into(self, out: &mut Output<Self>);

    /// Retrieve result and consume the hasher instance.
    #[inline]
    fn finalize_fixed(self) -> Output<Self> {
        let mut out = Default::default();
        self.finalize_into(&mut out);
        out
    }
}

/// Types which return fixed-sized result after finalization and reset
/// state into its initial value.
pub trait FixedOutputReset: FixedOutput + Reset {
    /// Write result into provided array and reset value to its initial state.
    fn finalize_into_reset(&mut self, out: &mut Output<Self>);

    /// Retrieve result and reset the hasher instance.
    #[inline]
    fn finalize_fixed_reset(&mut self) -> Output<Self> {
        let mut out = Default::default();
        self.finalize_into_reset(&mut out);
        out
    }
}

/// Resettable types.
pub trait Reset {
    /// Reset state to its initial value.
    fn reset(&mut self);
}

/// Types which consume data in blocks.
pub trait UpdateCore: BlockUser {
    /// Update state using the provided data blocks.
    fn update_blocks(&mut self, blocks: &[Block<Self>]);
}

/// Types which use [`DigestBuffer`] functionality.
pub trait BufferUser: BlockUser {
    /// Block buffer type over which value operates.
    type Buffer: DigestBuffer<Self::BlockSize>;
}

/// Core trait for hash functions with fixed output size.
pub trait FixedOutputCore: UpdateCore + BufferUser + OutputSizeUser {
    /// Finalize state using remaining data stored in the provided block buffer,
    /// write result into provided array using and leave value in a dirty state.
    fn finalize_fixed_core(&mut self, buffer: &mut Self::Buffer, out: &mut Output<Self>);
}

/// Trait which stores algorithm name constant, used in `Debug` implementations.
pub trait AlgorithmName {
    /// Write algorithm name into `f`.
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result;
}
