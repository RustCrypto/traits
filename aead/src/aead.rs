use crate::{AeadCore, Error, Result};
use alloc::vec::Vec;

/// High-level functionality of Authenticated Encryption with Associated Data (AEAD) algorithms.
pub trait Aead {
    /// Encrypt the given plaintext payload, and return the resulting
    /// ciphertext as a vector of bytes.
    ///
    /// # Errors
    /// AEAD algorithm implementations may return an error if the plaintext or AAD are too long.
    fn encrypt_into_vec(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt the given ciphertext slice, and return the resulting plaintext
    /// as a vector of bytes.
    ///
    /// # Errors
    /// - if the `ciphertext` is inauthentic (i.e. tag verification failure)
    /// - if the `ciphertext` is too long
    /// - if the `aad` is too long
    fn decrypt_into_vec(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// Encrypt plaintext in `buf` extending it as necessary.
    ///
    /// On success, `buf` will contain the resulting ciphertext,
    /// while on error it will be left intact.
    ///
    /// # Errors
    /// AEAD algorithm implementations may return an error if the plaintext or AAD are too long.
    #[inline]
    fn encrypt_within_vec(&self, nonce: &[u8], aad: &[u8], buf: &mut Vec<u8>) -> Result<()> {
        let res = self.encrypt_into_vec(nonce, aad, buf)?;
        *buf = res;
        Ok(())
    }

    /// Decrypt ciphertext in `buf` truncating it as necessary.
    ///
    /// On success, `buf` will contain the resulting plaintext,
    /// while on error it will be zeroized.
    ///
    /// # Errors
    /// - if the `ciphertext` is inauthentic (i.e. tag verification failure)
    /// - if the `ciphertext` is too long
    /// - if the `aad` is too long
    #[inline]
    fn decrypt_within_vec(&self, nonce: &[u8], aad: &[u8], buf: &mut Vec<u8>) -> Result<()> {
        let res = self.decrypt_into_vec(nonce, aad, buf);
        match res {
            Ok(pt) => {
                *buf = pt;
                Ok(())
            }
            Err(err) => {
                buf.fill(0);
                Err(err)
            }
        }
    }
}

impl<T: AeadCore> Aead for T {
    #[inline]
    fn encrypt_into_vec(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = nonce.try_into().map_err(|_| Error)?;
        self.encrypt_into(nonce, aad, plaintext, alloc_vec)
    }

    #[inline]
    fn decrypt_into_vec(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = nonce.try_into().map_err(|_| Error)?;
        self.decrypt_into(nonce, aad, ciphertext, alloc_vec)
    }

    #[inline]
    fn encrypt_within_vec(&self, nonce: &[u8], aad: &[u8], buf: &mut Vec<u8>) -> Result<()> {
        let nonce = nonce.try_into().map_err(|_| Error)?;
        self.encrypt_within(nonce, aad, buf, extend_vec)
    }

    #[inline]
    fn decrypt_within_vec(&self, nonce: &[u8], aad: &[u8], buf: &mut Vec<u8>) -> Result<()> {
        let nonce = nonce.try_into().map_err(|_| Error)?;
        self.decrypt_within(nonce, aad, buf, Vec::truncate)
    }
}

fn alloc_vec(len: usize) -> Vec<u8> {
    alloc::vec![0u8; len]
}

fn extend_vec(buf: &mut Vec<u8>, len: usize) {
    buf.resize(len, 0);
}
