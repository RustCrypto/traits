use inout::InOutBuf;
use crate::{BlockDecryptMut, BlockSizeUser, Block, BlockEncryptMut};

pub trait UnalignedBytesDecryptMut : BlockDecryptMut + BlockSizeUser {
    fn proc_tail(&self, blocks: &mut InOutBuf<'_, '_, Block<Self>>, tail: &mut InOutBuf<'_, '_, u8>) -> Result<(), TailError>;

    #[inline]
    fn decrypt_bytes_inout_mut<'inp, 'out>(
        &mut self,
        data: InOutBuf<'inp, 'out, u8>,
    ) -> Result<&'out [u8], TailError>
    {
        let n = data.len();
        let (mut blocks, mut tail) = data.into_chunks();
        self.decrypt_blocks_inout_mut(blocks.reborrow());
        if !tail.is_empty() {
            self.proc_tail(&mut blocks, &mut tail)?
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
    fn decrypt_bytes_mut<'a>(
        &mut self,
        buf: &'a mut [u8],
    ) -> Result<&'a [u8], TailError> {
        self.decrypt_bytes_inout_mut(buf.into())
    }

    /// Unaligned bytes input and decrypt buffer-to-buffer. Returns resulting plaintext slice.
    ///
    /// Returns [`TailError`] if length of output buffer is not sufficient.
    #[inline]
    fn decrypt_bytes_b2b_mut<'a>(
        &mut self,
        msg: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], TailError> {
        self.decrypt_bytes_inout_mut(InOutBuf::new(msg, out_buf).unwrap())
        // FIXME:  pass NotEqualError with TailError
        //self.decrypt_bytes_inout_mut(InOutBuf::new(msg, out_buf)?)
    }
}

pub trait UnalignedBytesEncryptMut : BlockEncryptMut + BlockSizeUser {
    fn proc_tail(&self, blocks: &mut InOutBuf<'_, '_, Block<Self>>, tail: &mut InOutBuf<'_, '_, u8>) -> Result<(), TailError>;

    #[inline]
    fn encrypt_bytes_inout_mut<'inp, 'out>(
        &mut self,
        data: InOutBuf<'inp, 'out, u8>,
    ) -> Result<&'out [u8], TailError>
    {
        let n = data.len();
        let (mut blocks, mut tail) = data.into_chunks();
        self.encrypt_blocks_inout_mut(blocks.reborrow());
        if !tail.is_empty() {
            self.proc_tail(&mut blocks, &mut tail)?
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
    fn encrypt_bytes_mut<'a>(
        &mut self,
        buf: &'a mut [u8],
    ) -> Result<&'a [u8], TailError> {
        self.encrypt_bytes_inout_mut(buf.into())
    }

    /// Unaligned bytes input and encrypt buffer-to-buffer. Returns resulting plaintext slice.
    ///
    /// Returns [`TailError`] if length of output buffer is not sufficient.
    #[inline]
    fn encrypt_bytes_b2b_mut<'a>(
        &mut self,
        msg: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], TailError> {
        self.encrypt_bytes_inout_mut(InOutBuf::new(msg, out_buf).unwrap())
        // FIXME:  pass NotEqualError with TailError
        //self.encrypt_bytes_inout_mut(InOutBuf::new(msg, out_buf)?)
    }
}

#[derive(Debug)]
pub struct TailError;