//! Low-level core API traits.
//!
//! Usage of traits in this module in user code is discouraged. Instead use
//! core algorithm wrapped by the wrapper types, which implement the
//! higher-level traits.
use crate::InvalidOutputSize;
use core::fmt;
use generic_array::{ArrayLength, GenericArray};

mod ct_variable;
mod rt_variable;
mod update;
mod xof_reader;

pub use ct_variable::CtVariableCoreWrapper;
pub use rt_variable::RtVariableCoreWrapper;
pub use update::UpdateCoreWrapper;
pub use xof_reader::XofReaderCoreWrapper;

/// Trait for updating hasher state with input data divided into blocks.
pub trait UpdateCore {
    /// Block size in bytes.
    type BlockSize: ArrayLength<u8>;

    /// Update the hasher state using the provided data.
    fn update_blocks(&mut self, blocks: &[GenericArray<u8, Self::BlockSize>]);
}

/// Core trait for hash functions with fixed output size.
pub trait FixedOutputCore: UpdateCore {
    /// Digest output size in bytes.
    type OutputSize: ArrayLength<u8>;

    /// Retrieve result into provided buffer using remaining data stored
    /// in the block buffer and leave hasher in a dirty state.
    fn finalize_fixed_core(
        &mut self,
        buffer: &mut block_buffer::BlockBuffer<Self::BlockSize>,
        out: &mut GenericArray<u8, Self::OutputSize>,
    );
}

/// Core trait for hash functions with extendable (XOF) output size.
pub trait ExtendableOutputCore: UpdateCore {
    /// XOF reader core state.
    type ReaderCore: XofReaderCore;

    /// Retrieve XOF reader using remaining data stored in the block buffer
    /// and leave hasher in a dirty state.
    fn finalize_xof_core(
        &mut self,
        buffer: &mut block_buffer::BlockBuffer<Self::BlockSize>,
    ) -> Self::ReaderCore;
}

/// Core reader trait for extendable-output function (XOF) result.
pub trait XofReaderCore {
    /// Block size in bytes.
    type BlockSize: ArrayLength<u8>;

    /// Read next XOF block.
    fn read_block(&mut self) -> GenericArray<u8, Self::BlockSize>;
}

/// Core trait for hash functions with variable output size.
pub trait VariableOutputCore: UpdateCore + Sized {
    /// Maximum output size.
    type MaxOutputSize: ArrayLength<u8>;

    /// Initialize hasher state for given output size.
    ///
    /// Returns [`InvalidOutputSize`] if `output_size` is equal to zero or
    /// bigger than `Self::MaxOutputSize`.
    fn new(output_size: usize) -> Result<Self, InvalidOutputSize>;

    /// Finalize hasher and return result of lenght `output_size` via closure `f`.
    ///
    /// `output_size` must be equal to `output_size` used during construction.
    fn finalize_variable_core(
        &mut self,
        buffer: &mut block_buffer::BlockBuffer<Self::BlockSize>,
        output_size: usize,
        f: impl FnOnce(&[u8]),
    );
}

/// Trait which stores algorithm name constant, used in `Debug` implementations.
pub trait AlgorithmName {
    /// Write algorithm name into `f`.
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result;
}
