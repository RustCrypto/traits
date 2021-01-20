use crate::{ExtendableOutput, FixedOutput, Reset, Update, XofReader};
use block_buffer::BlockBuffer;
use core::fmt;
use generic_array::{ArrayLength, GenericArray};

/// Trait which stores algorithm name constant, used in `Debug` implementations.
pub trait AlgorithmName {
    /// Algorithm name.
    const NAME: &'static str;
}

/// Trait for updating hasher state with input data divided into blocks.
pub trait UpdateCore {
    /// Block size in bytes.
    type BlockSize: ArrayLength<u8>;

    /// Update the hasher state using the provided data.
    fn update_blocks(&mut self, blocks: &[GenericArray<u8, Self::BlockSize>]);
}

/// Trait for fixed-output digest implementations to use to retrieve the
/// hash output.
///
/// Usage of this trait in user code is discouraged. Instead use core algorithm
/// wrapped by [`BlockBufferWrapper`], which implements the [`FixedOutput`]
/// trait.
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

/// Trait for extendable-output function (XOF) core implementations to use to
/// retrieve the hash output.
///
/// Usage of this trait in user code is discouraged. Instead use core algorithm
/// wrapped by [`BlockBufferWrapper`], which implements the
/// [`ExtendableOutput`] trait.
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

/// Wrapper around [`UpdateCore`] implementations.
///
/// It handles data buffering and implements the mid-level traits.
#[derive(Clone, Default)]
pub struct UpdateCoreWrapper<T: UpdateCore> {
    core: T,
    buffer: BlockBuffer<T::BlockSize>,
}

/// Wrapper around [`XofReaderCore`] implementations.
///
/// It handles data buffering and implements the mid-level traits.
#[derive(Clone, Default)]
pub struct XofReaderCoreWrapper<T: XofReaderCore> {
    core: T,
    buffer: BlockBuffer<T::BlockSize>,
}

impl<T: UpdateCore + AlgorithmName> fmt::Debug for UpdateCoreWrapper<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(T::NAME)?;
        f.write_str(" { .. }")
    }
}

impl<T: XofReaderCore + AlgorithmName> fmt::Debug for XofReaderCoreWrapper<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(T::NAME)?;
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

impl<R: XofReaderCore> XofReader for XofReaderCoreWrapper<R> {
    #[inline]
    fn read(&mut self, buffer: &mut [u8]) {
        let Self { core, buffer: buf } = self;
        buf.set_data(buffer, || core.read_block());
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

#[cfg(feature = "std")]
impl<R: XofReaderCore> std::io::Read for XofReaderCoreWrapper<R> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        XofReader::read(self, buf);
        Ok(buf.len())
    }
}
