use super::{
    AlgorithmName, ExtendableOutputCore, FixedOutputCore, UpdateCore, XofReaderCoreWrapper,
};
use crate::{ExtendableOutput, FixedOutput, Reset, Update};
use block_buffer::BlockBuffer;
use core::fmt;
use generic_array::GenericArray;

/// Wrapper around [`UpdateCore`] implementations.
///
/// It handles data buffering and implements the mid-level traits.
#[derive(Clone, Default)]
pub struct UpdateCoreWrapper<T: UpdateCore> {
    core: T,
    buffer: BlockBuffer<T::BlockSize>,
}

impl<T: UpdateCore + AlgorithmName> fmt::Debug for UpdateCoreWrapper<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        T::write_alg_name(f)?;
        f.write_str(" { .. }")
    }
}

impl<D: Default + UpdateCore> Reset for UpdateCoreWrapper<D> {
    #[inline]
    fn reset(&mut self) {
        self.core = Default::default();
        self.buffer.reset();
    }
}

impl<D: UpdateCore> Update for UpdateCoreWrapper<D> {
    #[inline]
    fn update(&mut self, input: &[u8]) {
        let Self { core, buffer } = self;
        buffer.digest_blocks(input, |blocks| core.update_blocks(blocks));
    }
}

impl<D: FixedOutputCore + Default> FixedOutput for UpdateCoreWrapper<D> {
    type OutputSize = D::OutputSize;

    #[inline]
    fn finalize_into(mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
        let Self { core, buffer } = &mut self;
        core.finalize_fixed_core(buffer, out);
    }

    #[inline]
    fn finalize_into_reset(&mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
        let Self { core, buffer } = self;
        core.finalize_fixed_core(buffer, out);
        self.reset();
    }
}

impl<D: ExtendableOutputCore + Default> ExtendableOutput for UpdateCoreWrapper<D> {
    type Reader = XofReaderCoreWrapper<D::ReaderCore>;

    #[inline]
    fn finalize_xof(mut self) -> Self::Reader {
        let Self { core, buffer } = &mut self;
        let reader_core = core.finalize_xof_core(buffer);
        XofReaderCoreWrapper {
            core: reader_core,
            buffer: Default::default(),
        }
    }

    #[inline]
    fn finalize_xof_reset(&mut self) -> Self::Reader {
        let Self { core, buffer } = self;
        let reader_core = core.finalize_xof_core(buffer);
        self.reset();
        XofReaderCoreWrapper {
            core: reader_core,
            buffer: Default::default(),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl<D: UpdateCore> std::io::Write for UpdateCoreWrapper<D> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Update::update(self, buf);
        Ok(buf.len())
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
