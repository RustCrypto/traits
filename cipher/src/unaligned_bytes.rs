use crate::{Block, BlockDecrypt, BlockEncrypt, BlockSizeUser};
use inout::InOutBuf;

pub trait UnalignedBytesDecrypt: BlockDecrypt + BlockSizeUser {
    /// In many cases, plaintext and ciphertext input is not divisible by the block size, and padding is often used.
    /// In practical use, however, this is not always done, and the termination may be handled by, for example, XOR.
    /// This trait and fn [`proc_tail`] divides the input into aligned blocks and an unaligned part([`tail`]),
    /// and then applies appropriate user-specified processing to the [`tail`].
    fn proc_tail(
        &self,
        blocks: &InOutBuf<'_, '_, Block<Self>>,
        tail: &InOutBuf<'_, '_, u8>,
    ) -> Result<(), TailError>;

    #[inline]
    fn decrypt_bytes_inout<'inp, 'out>(
        &self,
        data: InOutBuf<'inp, 'out, u8>,
    ) -> Result<&'out [u8], TailError> {
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
    fn decrypt_bytes<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], TailError> {
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
        // FIXME:  pass NotEqualError with TailError
        //self.decrypt_bytes_inout(InOutBuf::new(msg, out_buf)?)
    }
}

pub trait UnalignedBytesEncrypt: BlockEncrypt + BlockSizeUser {
    /// In many cases, plaintext and ciphertext input is not divisible by the block size, and padding is often used.
    /// In practical use, however, this is not always done, and the termination may be handled by, for example, XOR.
    /// This trait and fn [`proc_tail`] divides the input into aligned blocks and an unaligned part([`tail`]),
    /// and then applies appropriate user-specified processing to the [`tail`].
    fn proc_tail(
        &self,
        blocks: &InOutBuf<'_, '_, Block<Self>>,
        tail: &InOutBuf<'_, '_, u8>,
    ) -> Result<(), TailError>;

    #[inline]
    fn encrypt_bytes_inout<'inp, 'out>(
        &self,
        data: InOutBuf<'inp, 'out, u8>,
    ) -> Result<&'out [u8], TailError> {
        let n = data.len();

        let (mut blocks, tail) = data.into_chunks();
        self.encrypt_blocks_inout(blocks.reborrow());
        if !tail.is_empty() {
            self.proc_tail(&blocks, &tail)?
        }
        let out = unsafe {
            let ptr = blocks.into_raw().1 as *const u8;
            core::slice::from_raw_parts(ptr, n)
        };
        Ok(out)
    }

    /// Unaligned bytes input and encrypt in-place. Returns resulting plaintext slice.
    ///
    /// Returns [`TailError`] if length of output buffer is not sufficient.
    #[inline]
    fn encrypt_bytes<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], TailError> {
        self.encrypt_bytes_inout(buf.into())
    }

    /// Unaligned bytes input and encrypt buffer-to-buffer. Returns resulting plaintext slice.
    ///
    /// Returns [`TailError`] if length of output buffer is not sufficient.
    #[inline]
    fn encrypt_bytes_b2b<'a>(
        &self,
        msg: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], TailError> {
        self.encrypt_bytes_inout(InOutBuf::new(msg, out_buf).unwrap())
        // FIXME:  pass NotEqualError with TailError
        //self.encrypt_bytes_inout(InOutBuf::new(msg, out_buf)?)
    }
}

#[derive(Debug)]
pub struct TailError;
