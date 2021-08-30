//! Low-level core API traits.
//!
//! Usage of traits in this module in user code is discouraged. Instead use
//! core algorithm wrapped by the wrapper types, which implement the
//! higher-level traits.
use crate::InvalidOutputSize;
use crate::{ExtendableOutput, Reset};
use generic_array::ArrayLength;

pub use crypto_common::{
    AlgorithmName, Block, BlockUser, CoreWrapper, FixedOutputCore, UpdateCore,
};

mod ct_variable;
mod rt_variable;
mod xof_reader;

pub use ct_variable::CtVariableCoreWrapper;
pub use rt_variable::RtVariableCoreWrapper;
pub use xof_reader::XofReaderCoreWrapper;

/// Core trait for hash functions with extendable (XOF) output size.
pub trait ExtendableOutputCore: UpdateCore {
    /// XOF reader core state.
    type ReaderCore: XofReaderCore;

    /// Retrieve XOF reader using remaining data stored in the block buffer
    /// and leave hasher in a dirty state.
    fn finalize_xof_core(&mut self, buffer: &mut Self::Buffer) -> Self::ReaderCore;
}

/// Core reader trait for extendable-output function (XOF) result.
pub trait XofReaderCore: BlockUser {
    /// Read next XOF block.
    fn read_block(&mut self) -> Block<Self>;
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
        buffer: &mut Self::Buffer,
        output_size: usize,
        f: impl FnOnce(&[u8]),
    );
}

impl<D: ExtendableOutputCore + Default + Reset> ExtendableOutput for CoreWrapper<D> {
    type Reader = XofReaderCoreWrapper<D::ReaderCore>;

    #[inline]
    fn finalize_xof(self) -> Self::Reader {
        let (mut core, mut buffer) = self.decompose();
        let core = core.finalize_xof_core(&mut buffer);
        let buffer = Default::default();
        Self::Reader { core, buffer }
    }

    #[inline]
    fn finalize_xof_reset(&mut self) -> Self::Reader {
        self.apply_reset(|core, buffer| {
            let core = core.finalize_xof_core(buffer);
            let buffer = Default::default();
            Self::Reader { core, buffer }
        })
    }
}
