use crate::{
    AeadCore, Error, Result, Tag,
    TagPosition::{Postfix, Prefix},
};
use common::typenum::Unsigned;
use inout::InOutBuf;

/// Functionality of Authenticated Encryption with Associated Data (AEAD) algorithms
/// with variable nonce and tag size support.
///
/// <div class="warning">
/// Some algorithms support very short nonce and tag sizes. Users should exercise extreme caution
/// while using this trait since incorrect handling of nonces and tags may defeat security
/// provided by the algorithm.
/// </div>
pub trait VariableAead: AeadCore {
    /// Check if the provided nonce size is supported by the implementation.
    ///
    /// # Errors
    /// If the nonce size is not supported.
    fn check_nonce_size(nonce_size: usize) -> Result<()> {
        if nonce_size == Self::NonceSize::USIZE {
            Ok(())
        } else {
            Err(Error)
        }
    }

    /// Check if the provided tag size is supported by the implementation.
    ///
    /// # Errors
    /// If the tag size is not supported.
    fn check_tag_size(tag_size: usize) -> Result<()> {
        if tag_size == Self::TagSize::USIZE {
            Ok(())
        } else {
            Err(Error)
        }
    }

    /// Encrypt the data in the provided [`InOutBuf`] with variable nonce and tag sizes,
    /// writing the resulting tag into `tag_dst`.
    ///
    /// # Errors
    /// AEAD algorithm implementations may return an error if the plaintext or AAD are too long
    /// or an invalid nonce is used.
    #[inline]
    fn variable_encrypt_inout_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: InOutBuf<'_, '_, u8>,
        tag_dst: &mut [u8],
    ) -> Result<()> {
        let nonce = nonce.try_into().map_err(|_| Error)?;
        let tag_dst: &mut Tag<Self> = tag_dst.try_into().map_err(|_| Error)?;
        *tag_dst = self.encrypt_inout_detached(nonce, aad, buf)?;
        Ok(())
    }

    /// Decrypt the data in the provided [`InOutBuf`] with variable nonce and tag sizes,
    /// returning an error in the event the provided authentication tag is invalid
    /// for the given ciphertext (i.e. ciphertext is modified/unauthentic).
    ///
    /// # Errors
    /// - if the `ciphertext` is inauthentic (i.e. tag verification failure)
    /// - if the `ciphertext` is too long
    /// - if the `aad` is too long
    #[inline]
    fn variable_decrypt_inout_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: InOutBuf<'_, '_, u8>,
        tag: &[u8],
    ) -> Result<()> {
        let nonce = nonce.try_into().map_err(|_| Error)?;
        let tag = tag.try_into().map_err(|_| Error)?;
        self.decrypt_inout_detached(nonce, aad, buf, tag)
    }

    /// Encrypt the data in-place in the provided buffer with variable nonce and tag sizes,
    /// returning the authentication tag.
    ///
    /// # Errors
    /// AEAD algorithm implementations may return an error if the plaintext or AAD are too long
    /// or if provided nonce size is not supported.
    #[inline]
    fn variable_encrypt_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
        tag_dst: &mut [u8],
    ) -> Result<()> {
        self.variable_encrypt_inout_detached(nonce, aad, buf.into(), tag_dst)
    }

    /// Decrypt the data in-place in the provided buffer with variable nonce and tag sizes,
    /// returning an error in the event the provided authentication tag is invalid
    /// for the given ciphertext (i.e. ciphertext is modified/unauthentic).
    ///
    /// # Errors
    /// - if the `ciphertext` is inauthentic (i.e. tag verification failure)
    /// - if the `ciphertext` is too long
    /// - if the `aad` is too long
    #[inline]
    fn variable_decrypt_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8],
    ) -> Result<()> {
        self.variable_decrypt_inout_detached(nonce, aad, buf.into(), tag)
    }

    /// Encrypt `plaintext` into a buffer allocated with `allocate`
    /// with variable nonce and tag sizes.
    ///
    /// # Errors
    /// AEAD algorithm implementations may return an error if the plaintext or AAD are too long.
    ///
    /// # Panics
    /// If `allocate` returns a buffer with length in bytes not equal to the provided argument.
    #[inline]
    fn variable_encrypt_into<B: AsMut<[u8]>>(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        tag_size: usize,
        allocate: impl FnOnce(usize) -> B,
    ) -> Result<B> {
        let ct_len = plaintext.len().checked_add(tag_size).ok_or(Error)?;

        let mut ct_tag = allocate(ct_len);
        assert_eq!(ct_tag.as_mut().len(), ct_len);

        let (ct_dst, tag_dst) = match Self::TAG_POSITION {
            Postfix => ct_tag.as_mut().split_at_mut(plaintext.len()),
            Prefix => {
                let (tag_dst, ct_dst) = ct_tag.as_mut().split_at_mut(tag_size);
                (ct_dst, tag_dst)
            }
        };

        let buf = InOutBuf::new(plaintext, ct_dst)
            .expect("`plaintext` and `ct_dst` always have the same length");

        self.variable_encrypt_inout_detached(nonce, aad, buf, tag_dst)?;

        Ok(ct_tag)
    }

    /// Decrypt `ciphertext` into a buffer allocated with `allocate`
    /// with variable nonce and tag sizes.
    ///
    /// # Errors
    /// - if the `ciphertext` is inauthentic (i.e. tag verification failure)
    /// - if the `ciphertext` is too long
    /// - if the `aad` is too long
    ///
    /// # Panics
    /// If `allocate` returns a buffer with length in bytes not equal to the provided argument.
    #[inline]
    fn variable_decrypt_into<B: AsMut<[u8]>>(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag_size: usize,
        allocate: impl FnOnce(usize) -> B,
    ) -> Result<B> {
        let pt_len = ciphertext.len().checked_sub(tag_size).ok_or(Error)?;

        let (ct, tag) = match Self::TAG_POSITION {
            Postfix => ciphertext.split_at(pt_len),
            Prefix => {
                let (tag, ct) = ciphertext.split_at(tag_size);
                (ct, tag)
            }
        };

        let mut pt_dst = allocate(pt_len);
        assert_eq!(pt_dst.as_mut().len(), pt_len);

        let buf = InOutBuf::new(ct, pt_dst.as_mut())
            .expect("`ct` and `pt_dst` should always have the same length");
        self.variable_decrypt_inout_detached(nonce, aad, buf, tag)?;

        Ok(pt_dst)
    }

    /// Encrypt data in `buf` with variable nonce and tag sizes extending the buffer with `extend`.
    ///
    /// # Errors
    /// AEAD algorithm implementations may return an error if the plaintext or AAD are too long.
    ///
    /// # Panics
    /// If `extend` does not extend the buffer to the specified length in bytes.
    #[inline]
    fn variable_encrypt_within<B: AsMut<[u8]>>(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut B,
        tag_size: usize,
        extend: impl FnOnce(&mut B, usize),
    ) -> Result<()> {
        let pt_len = buf.as_mut().len();
        let ct_len = pt_len.checked_add(tag_size).ok_or(Error)?;

        extend(buf, ct_len);
        let buf = buf.as_mut();
        assert_eq!(buf.len(), ct_len);

        let (pt, tag_dst) = match Self::TAG_POSITION {
            Postfix => buf.split_at_mut(pt_len),
            Prefix => {
                buf.copy_within(..pt_len, tag_size);
                let (tag_dst, pt) = buf.split_at_mut(tag_size);
                (pt, tag_dst)
            }
        };

        self.variable_encrypt_inout_detached(nonce, aad, pt.into(), tag_dst)
            // On failure the `pt` part should be zeroized by the encrypt function
            .inspect_err(|_| tag_dst.fill(0))
    }

    /// Decrypt data in `buf` with variable nonce and tag sizes
    /// truncating the buffer with `truncate`.
    ///
    /// # Errors
    /// - if the `ciphertext` is inauthentic (i.e. tag verification failure)
    /// - if the `ciphertext` is too long
    /// - if the `aad` is too long
    ///
    /// # Panics
    /// If `truncate` does not truncate the buffer to the specified length in bytes.
    #[inline]
    fn variable_decrypt_within<B: AsMut<[u8]>>(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut B,
        tag_size: usize,
        truncate: impl FnOnce(&mut B, usize),
    ) -> Result<()> {
        let buf_mut = buf.as_mut();
        let ct_len = buf_mut.len().checked_sub(tag_size).ok_or(Error)?;

        let (ct, tag) = match Self::TAG_POSITION {
            Postfix => buf_mut.split_at_mut(ct_len),
            Prefix => {
                let (tag, ct) = buf_mut.split_at_mut(tag_size);
                (ct, tag)
            }
        };

        self.variable_decrypt_inout_detached(nonce, aad, ct.into(), tag)
            // On failure the `ct` part should be zeroized by the decryption function
            .inspect_err(|_| tag.fill(0))?;

        if Self::TAG_POSITION == Prefix {
            buf_mut.copy_within(tag_size.., 0);
        }

        truncate(buf, ct_len);
        assert_eq!(buf.as_mut().len(), ct_len);

        Ok(())
    }
}
