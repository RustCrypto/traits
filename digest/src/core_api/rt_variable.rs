use super::{AlgorithmName, VariableOutputCore};
use crate::{InvalidOutputSize, VariableOutput};
use block_buffer::BlockBuffer;
use generic_array::typenum::Unsigned;
use core::fmt;

/// Wrapper around [`VariableOutputCore`] which selects output size
/// at run time.
#[derive(Clone)]
pub struct RtVariableCoreWrapper<T: VariableOutputCore> {
    core: T,
    buffer: BlockBuffer<T::BlockSize>,
    output_size: usize,
}

impl<T: VariableOutputCore> VariableOutput for RtVariableCoreWrapper<T> {
    const MAX_OUTPUT_SIZE: usize = T::MaxOutputSize::USIZE;

    fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
        let buffer = Default::default();
        T::new(output_size).map(|core| Self {
            core,
            buffer,
            output_size,
        })
    }

    fn output_size(&self) -> usize {
        self.output_size
    }

    fn finalize_variable(mut self, f: impl FnOnce(&[u8])) {
        let Self {
            core,
            buffer,
            output_size,
        } = &mut self;
        core.finalize_variable_core(buffer, *output_size, f);
    }

    fn finalize_variable_reset(&mut self, f: impl FnOnce(&[u8])) {
        let Self {
            core,
            buffer,
            output_size,
        } = self;
        core.finalize_variable_core(buffer, *output_size, f);
        buffer.reset();
        // For correct implementations `new` should always return `Ok`
        // since we have already verified that `output_size` lies in a valid range.
        if let Ok(v) = T::new(*output_size) {
            *core = v;
        } else {
            debug_assert!(false);
        }
    }
}

impl<T: VariableOutputCore + AlgorithmName> fmt::Debug for RtVariableCoreWrapper<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        T::write_alg_name(f)?;
        f.write_str(" { .. }")
    }
}
