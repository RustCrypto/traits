use super::{AlgorithmName, XofReaderCore};
use crate::XofReader;
use block_buffer::ReadBuffer;
use core::fmt;

/// Wrapper around [`XofReaderCore`] implementations.
///
/// It handles data buffering and implements the mid-level traits.
#[derive(Clone, Default)]
pub struct XofReaderCoreWrapper<T>
where
    T: XofReaderCore,
{
    pub(super) core: T,
    pub(super) buffer: ReadBuffer<T::BlockSize>,
}

impl<T> fmt::Debug for XofReaderCoreWrapper<T>
where
    T: XofReaderCore + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        T::write_alg_name(f)?;
        f.write_str(" { .. }")
    }
}

impl<T> XofReader for XofReaderCoreWrapper<T>
where
    T: XofReaderCore,
{
    #[inline]
    fn read(&mut self, buffer: &mut [u8]) {
        let Self { core, buffer: buf } = self;
        buf.read(buffer, |block| *block = core.read_block());
    }
}

#[cfg(feature = "std")]
impl<T> std::io::Read for XofReaderCoreWrapper<T>
where
    T: XofReaderCore,
{
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        XofReader::read(self, buf);
        Ok(buf.len())
    }
}

impl<T: XofReaderCore> Drop for XofReaderCoreWrapper<T> {
    #[inline]
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize;
            self.buffer.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl<T: XofReaderCore + zeroize::ZeroizeOnDrop> zeroize::ZeroizeOnDrop for XofReaderCoreWrapper<T> {}
