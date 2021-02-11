use super::{AlgorithmName, XofReaderCore};
use crate::XofReader;
use core::fmt;
use crypto_common::block_buffer::BlockBuffer;

/// Wrapper around [`XofReaderCore`] implementations.
///
/// It handles data buffering and implements the mid-level traits.
#[derive(Clone, Default)]
pub struct XofReaderCoreWrapper<T: XofReaderCore> {
    pub(super) core: T,
    pub(super) buffer: BlockBuffer<T::BlockSize>,
}

impl<T: XofReaderCore + AlgorithmName> fmt::Debug for XofReaderCoreWrapper<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        T::write_alg_name(f)?;
        f.write_str(" { .. }")
    }
}

impl<R: XofReaderCore> XofReader for XofReaderCoreWrapper<R> {
    #[inline]
    fn read(&mut self, buffer: &mut [u8]) {
        let Self { core, buffer: buf } = self;
        buf.set_data(buffer, || core.read_block());
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl<R: XofReaderCore> std::io::Read for XofReaderCoreWrapper<R> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        XofReader::read(self, buf);
        Ok(buf.len())
    }
}
