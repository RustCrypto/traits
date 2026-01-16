//! Traits which define functionality of asynchronous (a.k.a. self-synchronizing) stream ciphers.

use crate::block::{BlockModeDecrypt, BlockModeEncrypt};
use crypto_common::Block;
use inout::{InOutBuf, NotEqualError};

/// Asynchronous stream cipher encryptor.
pub trait AsyncStreamCipherCoreEncrypt: BlockModeEncrypt {
    /// Encrypt data using `InOutBuf`.
    fn encrypt_inout(mut self, data: InOutBuf<'_, '_, u8>) {
        let (blocks, mut tail) = data.into_chunks();
        self.encrypt_blocks_inout(blocks);
        let n = tail.len();
        if n != 0 {
            let mut block = Block::<Self>::default();
            block[..n].copy_from_slice(tail.get_in());
            self.encrypt_block(&mut block);
            tail.get_out().copy_from_slice(&block[..n]);
        }
    }

    /// Encrypt data in place.
    fn encrypt(self, buf: &mut [u8]) {
        self.encrypt_inout(buf.into());
    }

    /// Encrypt data from buffer to buffer.
    fn encrypt_b2b(self, in_buf: &[u8], out_buf: &mut [u8]) -> Result<(), NotEqualError> {
        InOutBuf::new(in_buf, out_buf).map(|b| self.encrypt_inout(b))
    }
}

/// Asynchronous stream cipher decryptor.
pub trait AsyncStreamCipherCoreDecrypt: BlockModeDecrypt {
    /// Decrypt data using `InOutBuf`.
    fn decrypt_inout(mut self, data: InOutBuf<'_, '_, u8>) {
        let (blocks, mut tail) = data.into_chunks();
        self.decrypt_blocks_inout(blocks);
        let n = tail.len();
        if n != 0 {
            let mut block = Block::<Self>::default();
            block[..n].copy_from_slice(tail.get_in());
            self.decrypt_block(&mut block);
            tail.get_out().copy_from_slice(&block[..n]);
        }
    }

    /// Decrypt data in place.
    fn decrypt(self, buf: &mut [u8]) {
        self.decrypt_inout(buf.into());
    }

    /// Decrypt data from buffer to buffer.
    fn decrypt_b2b(self, in_buf: &[u8], out_buf: &mut [u8]) -> Result<(), NotEqualError> {
        InOutBuf::new(in_buf, out_buf).map(|b| self.decrypt_inout(b))
    }
}
