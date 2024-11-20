use crate::Result;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "bytes")]
use bytes::BytesMut;

#[cfg(feature = "arrayvec")]
use arrayvec::ArrayVec;

/// In-place encryption/decryption byte buffers.
///
/// This trait defines the set of methods needed to support in-place operations
/// on a `Vec`-like data type.
pub trait Buffer: AsMut<[u8]> {
    /// Resizes buffer to the requested length.
    ///
    /// If buffer is smaller than `len`, fills it with zeros. Otherwise, truncates it to `len`.
    fn resize(&mut self, len: usize) -> Result<()>;

    /// Extend this buffer from the given slice
    fn extend_from_slice(&mut self, other: &[u8]) -> Result<()>;

    /// Truncate this buffer to the given size
    fn truncate(&mut self, len: usize);
}

#[cfg(feature = "alloc")]
impl Buffer for Vec<u8> {
    fn resize(&mut self, len: usize) -> Result<()> {
        Vec::resize(self, len, 0);
        Ok(())
    }

    fn extend_from_slice(&mut self, other: &[u8]) -> Result<()> {
        Vec::extend_from_slice(self, other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        Vec::truncate(self, len);
    }
}

#[cfg(feature = "bytes")]
impl Buffer for BytesMut {
    fn resize(&mut self, len: usize) -> Result<()> {
        BytesMut::resize(self, len, 0);
        Ok(())
    }

    fn extend_from_slice(&mut self, other: &[u8]) -> Result<()> {
        BytesMut::extend_from_slice(self, other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        BytesMut::truncate(self, len);
    }
}

#[cfg(feature = "arrayvec")]
impl<const N: usize> Buffer for ArrayVec<u8, N> {
    fn resize(&mut self, len: usize) -> Result<()> {
        if let Some(ext_len) = len.checked_sub(self.len()) {
            let buf = &[0u8; N][..ext_len];
            self.try_extend_from_slice(buf).map_err(|_| crate::Error)
        } else {
            self.truncate(len);
            Ok(())
        }
    }

    fn extend_from_slice(&mut self, other: &[u8]) -> Result<()> {
        ArrayVec::try_extend_from_slice(self, other).map_err(|_| crate::Error)
    }

    fn truncate(&mut self, len: usize) {
        ArrayVec::truncate(self, len);
    }
}

#[cfg(feature = "heapless")]
impl<const N: usize> Buffer for heapless::Vec<u8, N> {
    fn resize(&mut self, len: usize) -> Result<()> {
        heapless::Vec::resize(self, len, 0).map_err(|_| crate::Error)
    }

    fn extend_from_slice(&mut self, other: &[u8]) -> Result<()> {
        heapless::Vec::extend_from_slice(self, other).map_err(|_| crate::Error)
    }

    fn truncate(&mut self, len: usize) {
        heapless::Vec::truncate(self, len);
    }
}
