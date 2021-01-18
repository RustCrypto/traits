use crate::{ExtendableOutput, FixedOutput, Reset, Update, XofReader};
use block_buffer::BlockBuffer;
use generic_array::{ArrayLength, GenericArray};

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
/// wrapped by [`crate::CoreWrapper`], which implements the [`FixedOutput`]
/// trait.
pub trait FixedOutputCore: crate::UpdateCore {
    /// Digest output size in bytes.
    type OutputSize: ArrayLength<u8>;

    /// Retrieve result into provided buffer using remaining data stored
    /// in the block buffer and leave hasher in a dirty state.
    ///
    /// This method is expected to only be called once unless [`Reset::reset`]
    /// is called, after which point it can be called again and reset again
    /// (and so on).
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
/// wrapped by [`crate::CoreWrapper`], which implements the
/// [`ExtendableOutput`] trait.
pub trait ExtendableOutputCore: crate::UpdateCore {
    /// XOF reader core state.
    type ReaderCore: XofReaderCore;

    /// Retrieve XOF reader using remaining data stored in the block buffer
    /// and leave hasher in a dirty state.
    ///
    /// This method is expected to only be called once unless [`Reset::reset`]
    /// is called, after which point it can be called again and reset again
    /// (and so on).
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

/// Wrapper around core trait implementations.
///
/// It handles data buffering and implements the mid-level traits.
#[derive(Clone, Default)]
pub struct CoreWrapper<C, BlockSize: ArrayLength<u8>> {
    core: C,
    buffer: BlockBuffer<BlockSize>,
}

impl<D: Reset + UpdateCore> Reset for CoreWrapper<D, D::BlockSize> {
    #[inline]
    fn reset(&mut self) {
        self.core.reset();
        self.buffer.reset();
    }
}

impl<D: UpdateCore> Update for CoreWrapper<D, D::BlockSize> {
    #[inline]
    fn update(&mut self, input: &[u8]) {
        let Self { core, buffer } = self;
        buffer.digest_blocks(input, |blocks| core.update_blocks(blocks));
    }
}

impl<D: FixedOutputCore + Reset> FixedOutput for CoreWrapper<D, D::BlockSize> {
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

impl<R: XofReaderCore> XofReader for CoreWrapper<R, R::BlockSize> {
    #[inline]
    fn read(&mut self, buffer: &mut [u8]) {
        let Self { core, buffer: buf } = self;
        buf.set_data(buffer, || core.read_block());
    }
}

impl<D: ExtendableOutputCore + Reset> ExtendableOutput for CoreWrapper<D, D::BlockSize> {
    type Reader = CoreWrapper<D::ReaderCore, <D::ReaderCore as XofReaderCore>::BlockSize>;

    #[inline]
    fn finalize_xof(mut self) -> Self::Reader {
        let Self { core, buffer } = &mut self;
        let reader_core = core.finalize_xof_core(buffer);
        CoreWrapper {
            core: reader_core,
            buffer: Default::default(),
        }
    }

    #[inline]
    fn finalize_xof_reset(&mut self) -> Self::Reader {
        let Self { core, buffer } = self;
        let reader_core = core.finalize_xof_core(buffer);
        self.reset();
        CoreWrapper {
            core: reader_core,
            buffer: Default::default(),
        }
    }
}

#[cfg(feature = "std")]
impl<D: UpdateCore> std::io::Write for CoreWrapper<D, D::BlockSize> {
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
impl<R: XofReaderCore> std::io::Read for CoreWrapper<R, R::BlockSize> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        XofReader::read(self, buf);
        Ok(buf.len())
    }
}
