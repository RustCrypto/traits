use inout::InOutBuf;
use crate::{BlockDecrypt, BlockSizeUser, Block};

pub trait UnalignedBytesDecrypt : BlockDecrypt + BlockSizeUser {
    fn proc_tail(&self, blocks: &InOutBuf<'_, '_, Block<Self>>, tail: &InOutBuf<'_, '_, u8>) -> Result<(), TailError>;

    #[inline]
    fn decrypt_bytes_inout<'inp, 'out>(
        &self,
        data: InOutBuf<'inp, 'out, u8>,
    ) -> Result<&'out [u8], TailError>
    {
        let n = data.len();

        let (mut blocks, tail) = data.into_chunks();
        self.decrypt_blocks_inout(blocks.reborrow());
        if !tail.is_empty() {
            self.proc_tail(&blocks, &tail)?
        }
        let out = unsafe {
            let ptr = blocks.into_raw().1 as *const u8;
            core::slice::from_raw_parts(ptr, n)
        };
        Ok(out)
    }

    /// Unaligned bytes input and decrypt in-place. Returns resulting plaintext slice.
    ///
    /// Returns [`TailError`] if length of output buffer is not sufficient.
    #[inline]
    fn decrypt_bytes<'a>(
        &self,
        buf: &'a mut [u8],
    ) -> Result<&'a [u8], TailError> {
        self.decrypt_bytes_inout(buf.into())
    }

    /// Unaligned bytes input and decrypt buffer-to-buffer. Returns resulting plaintext slice.
    ///
    /// Returns [`TailError`] if length of output buffer is not sufficient.
    #[inline]
    fn decrypt_bytes_b2b<'a>(
        &self,
        msg: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], TailError> {
        self.decrypt_bytes_inout(InOutBuf::new(msg, out_buf).unwrap())
    }
}

#[derive(Debug)]
pub struct TailError;