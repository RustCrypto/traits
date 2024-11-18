use inout::{InOutBuf, InOutBufReserved};

use crate::{Aead, Buffer, Error, Result};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

mod sealed {
    pub trait Sealed {}
}

/// Object-safe variant of the [`Aead`] trait.
///
/// This trait is implemented automaticlly for all types which implement the [`Aead`] trait.
pub trait DynAead: sealed::Sealed {
    fn postfix_encrypt_inout<'out>(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: InOutBufReserved<'_, 'out, u8>,
    ) -> Result<&'out mut [u8]>;

    fn postfix_decrypt_inout<'out>(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: InOutBuf<'_, 'out, u8>,
    ) -> Result<&'out mut [u8]>;

    fn postfix_encrypt_inplace<'out>(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &'out mut [u8],
        plaintext_len: usize,
    ) -> Result<&'out mut [u8]>;

    fn postfix_decrypt_inplace<'out>(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &'out mut [u8],
    ) -> Result<&'out mut [u8]>;

    fn postfix_encrypt_to_buf<'out>(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        plaintext: &[u8],
        buffer: &'out mut [u8],
    ) -> Result<&'out mut [u8]>;

    fn postfix_decrypt_to_buf<'out>(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        ciphertext: &[u8],
        buffer: &'out mut [u8],
    ) -> Result<&'out mut [u8]>;

    fn encrypt_to_buffer2(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        plaintext: &[u8],
        buffer: &mut dyn Buffer,
    ) -> Result<()>;

    fn decrypt_to_buffer2(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        ciphertext: &[u8],
        buffer: &mut dyn Buffer,
    ) -> Result<()>;

    #[cfg(feature = "alloc")]
    fn encrypt_to_vec(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>>;

    #[cfg(feature = "alloc")]
    fn decrypt_to_vec(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>>;
}

impl<T: Aead> sealed::Sealed for T {}

impl<T: Aead> DynAead for T {
    fn postfix_encrypt_inout<'out>(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: InOutBufReserved<'_, 'out, u8>,
    ) -> Result<&'out mut [u8]> {
        let nonce = nonce.try_into().map_err(|_| Error)?;
        Aead::postfix_encrypt_inout(self, nonce, associated_data, buffer)
    }

    fn postfix_decrypt_inout<'out>(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: InOutBuf<'_, 'out, u8>,
    ) -> Result<&'out mut [u8]> {
        let nonce = nonce.try_into().map_err(|_| Error)?;
        Aead::postfix_decrypt_inout(self, nonce, associated_data, buffer)
    }

    fn postfix_encrypt_inplace<'out>(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &'out mut [u8],
        plaintext_len: usize,
    ) -> Result<&'out mut [u8]> {
        let nonce = nonce.try_into().map_err(|_| Error)?;
        Aead::postfix_encrypt_inplace(self, nonce, associated_data, buffer, plaintext_len)
    }

    fn postfix_decrypt_inplace<'out>(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &'out mut [u8],
    ) -> Result<&'out mut [u8]> {
        let nonce = nonce.try_into().map_err(|_| Error)?;
        Aead::postfix_decrypt_inplace(self, nonce, associated_data, buffer)
    }

    fn postfix_encrypt_to_buf<'out>(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        plaintext: &[u8],
        buffer: &'out mut [u8],
    ) -> Result<&'out mut [u8]> {
        let nonce = nonce.try_into().map_err(|_| Error)?;
        Aead::postfix_encrypt_to_buf(self, nonce, associated_data, plaintext, buffer)
    }

    fn postfix_decrypt_to_buf<'out>(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        ciphertext: &[u8],
        buffer: &'out mut [u8],
    ) -> Result<&'out mut [u8]> {
        let nonce = nonce.try_into().map_err(|_| Error)?;
        Aead::postfix_decrypt_to_buf(self, nonce, associated_data, ciphertext, buffer)
    }

    fn encrypt_to_buffer2(
        &self,
        nonce: &[u8],
        aad: &[u8],
        msg: &[u8],
        buffer: &mut dyn Buffer,
    ) -> Result<()> {
        let nonce = nonce.try_into().map_err(|_| Error)?;
        let payload = crate::Payload { aad, msg };
        Aead::encrypt_to_buffer(self, nonce, payload, buffer)
    }

    fn decrypt_to_buffer2(
        &self,
        nonce: &[u8],
        aad: &[u8],
        msg: &[u8],
        buffer: &mut dyn Buffer,
    ) -> Result<()> {
        let nonce = nonce.try_into().map_err(|_| Error)?;
        let payload = crate::Payload { aad, msg };
        Aead::decrypt_to_buffer(self, nonce, payload, buffer)
    }

    #[cfg(feature = "alloc")]
    fn encrypt_to_vec(&self, nonce: &[u8], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
        let nonce = nonce.try_into().map_err(|_| Error)?;
        let payload = crate::Payload { aad, msg };
        Aead::encrypt_to_vec(self, nonce, payload)
    }

    #[cfg(feature = "alloc")]
    fn decrypt_to_vec(&self, nonce: &[u8], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
        let nonce = nonce.try_into().map_err(|_| Error)?;
        let payload = crate::Payload { aad, msg };
        Aead::decrypt_to_vec(self, nonce, payload)
    }
}

// Ensure that `DynAead` is an object-safe trait
#[allow(dead_code)]
fn foo(_: &dyn DynAead) {}
