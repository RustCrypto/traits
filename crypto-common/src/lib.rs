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

use generic_array::{
    typenum::{type_operators::IsLess, U256},
    ArrayLength, GenericArray,
};

pub use block_buffer;

mod core_api;
mod init;

pub use core_api::*;
pub use init::*;

/// Block on which [`BlockUser`] implementors operate.
pub type Block<B> = GenericArray<u8, <B as BlockUser>::BlockSize>;

/// Types which process data in blocks.
pub trait BlockUser {
    /// Size of the block in bytes.
    type BlockSize: ArrayLength<u8> + IsLess<U256> + 'static;
}

impl<Alg: BlockUser> BlockUser for &Alg {
    type BlockSize = Alg::BlockSize;
}

/// Trait which allows consumption of data.
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
/// state into its initial value.
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

/// Trait resetting of state to its initial value.
pub trait Reset {
    /// Reset state to its initial value.
    fn reset(&mut self);
}
