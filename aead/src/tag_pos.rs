use crate::{AeadCore, Error, Nonce, Result};
use common::typenum::Unsigned;
use inout::InOutBuf;

/// Enum which specifies tag position used by an AEAD algorithm.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TagPosition {
    /// Postfix tag
    Postfix,
    /// Prefix tag
    Prefix,
}

macro_rules! encrypt_into {
    ($plaintext:ident, $allocate:ident, $encrypt:expr) => {{
        let tag_len = Self::TagSize::USIZE;
        let ct_len = $plaintext.len().checked_add(tag_len).ok_or(Error)?;

        let mut ct_tag = $allocate(ct_len);
        assert_eq!(ct_tag.as_mut().len(), ct_len);

        let (ct_dst, tag_dst) = match Self::TAG_POSITION {
            TagPosition::Postfix => ct_tag.as_mut().split_at_mut($plaintext.len()),
            TagPosition::Prefix => {
                let (tag_dst, ct_dst) = ct_tag.as_mut().split_at_mut(tag_len);
                (ct_dst, tag_dst)
            }
        };

        let buf =
            InOutBuf::new($plaintext, ct_dst).expect("`msg` and `ct_dst` have the same length");
        let tag = $encrypt(buf)?;
        tag_dst.copy_from_slice(&tag);

        Ok(ct_tag)
    }};
}

macro_rules! decrypt_into {
    ($ciphertext:ident, $allocate:ident, $decrypt:expr) => {{
        let tag_len = Self::TagSize::USIZE;
        let pt_len = $ciphertext.len().checked_sub(tag_len).ok_or(Error)?;

        let (ct, tag) = match Self::TAG_POSITION {
            TagPosition::Postfix => $ciphertext.split_at(pt_len),
            TagPosition::Prefix => {
                let (tag, ct) = $ciphertext.split_at(tag_len);
                (ct, tag)
            }
        };

        let mut pt_dst = $allocate(pt_len);
        assert_eq!(pt_dst.as_mut().len(), pt_len);

        let tag = tag.try_into().expect("`tag` has correct length");
        let buf = InOutBuf::new(ct, pt_dst.as_mut())
            .expect("`ct` and `pt_dst` should have the same length");
        $decrypt(buf, tag)?;

        Ok(pt_dst)
    }};
}

macro_rules! encrypt_within {
    ($buf:ident, $extend:ident, $encrypt:expr) => {{
        let tag_len = Self::TagSize::USIZE;
        let pt_len = $buf.as_mut().len();
        let ct_len = pt_len.checked_add(tag_len).ok_or(Error)?;

        $extend($buf, ct_len);
        let buf = $buf.as_mut();
        assert_eq!(buf.len(), ct_len);

        let (pt_dst, tag_dst) = match Self::TAG_POSITION {
            TagPosition::Postfix => buf.split_at_mut(pt_len),
            TagPosition::Prefix => {
                buf.copy_within(..pt_len, tag_len);
                let (tag_dst, ct_dst) = $buf.as_mut().split_at_mut(tag_len);
                (ct_dst, tag_dst)
            }
        };

        let tag = $encrypt(InOutBuf::from(pt_dst))?;
        tag_dst.copy_from_slice(&tag);

        Ok(())
    }};
}

macro_rules! decrypt_within {
    ($buf:ident, $truncate:ident, $decrypt:expr) => {{
        let tag_len = Self::TagSize::USIZE;
        let ct_len = $buf.as_mut().len().checked_sub(tag_len).ok_or(Error)?;

        let (ct, tag) = match Self::TAG_POSITION {
            TagPosition::Postfix => $buf.as_mut().split_at_mut(ct_len),
            TagPosition::Prefix => {
                let (tag, ct) = $buf.as_mut().split_at_mut(tag_len);
                (ct, tag)
            }
        };

        let tag = (&*tag).try_into().expect("`tag` has correct length");
        $decrypt(ct.into(), tag)?;

        if Self::TAG_POSITION == TagPosition::Prefix {
            $buf.as_mut().copy_within(tag_len.., 0);
        }

        $truncate($buf, ct_len);
        assert_eq!($buf.as_mut().len(), ct_len);

        Ok(())
    }};
}

/// Trait implemented for AEAD modes which specify tag position in ciphertext.
#[allow(missing_docs, clippy::missing_errors_doc)] // TODO: fix
pub trait AeadWithTag: AeadCore {
    /// The AEAD tag position.
    const TAG_POSITION: TagPosition;

    #[inline]
    fn encrypt_into<B: AsMut<[u8]>>(
        &self,
        nonce: &Nonce<Self>,
        aad: &[u8],
        plaintext: &[u8],
        allocate: impl FnOnce(usize) -> B,
    ) -> Result<B> {
        encrypt_into!(plaintext, allocate, |buf| {
            self.encrypt_inout_detached(nonce, aad, buf)
        })
    }

    #[inline]
    fn encrypt_into_with_var_nonce<B: AsMut<[u8]>>(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        allocate: impl FnOnce(usize) -> B,
    ) -> Result<B> {
        encrypt_into!(plaintext, allocate, |buf| {
            self.encrypt_inout_with_var_nonce_detached(nonce, aad, buf)
        })
    }

    #[inline]
    fn decrypt_into<B: AsMut<[u8]>>(
        &self,
        nonce: &Nonce<Self>,
        aad: &[u8],
        ciphertext: &[u8],
        allocate: impl FnOnce(usize) -> B,
    ) -> Result<B> {
        decrypt_into!(ciphertext, allocate, |buf, tag| {
            self.decrypt_inout_detached(nonce, aad, buf, tag)
        })
    }

    #[inline]
    fn decrypt_into_with_var_nonce<B: AsMut<[u8]>>(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        allocate: impl FnOnce(usize) -> B,
    ) -> Result<B> {
        decrypt_into!(ciphertext, allocate, |buf, tag| {
            self.decrypt_inout_with_var_nonce_detached(nonce, aad, buf, tag)
        })
    }

    #[inline]
    fn encrypt_within<B: AsMut<[u8]>>(
        &self,
        nonce: &Nonce<Self>,
        aad: &[u8],
        buf: &mut B,
        extend: impl FnOnce(&mut B, usize),
    ) -> Result<()> {
        encrypt_within!(buf, extend, |buf| {
            self.encrypt_inout_detached(nonce, aad, buf)
        })
    }

    #[inline]
    fn encrypt_within_with_var_nonce<B: AsMut<[u8]>>(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut B,
        extend: impl FnOnce(&mut B, usize),
    ) -> Result<()> {
        encrypt_within!(buf, extend, |buf| {
            self.encrypt_inout_with_var_nonce_detached(nonce, aad, buf)
        })
    }

    #[inline]
    fn decrypt_within<B: AsMut<[u8]>>(
        &self,
        nonce: &Nonce<Self>,
        aad: &[u8],
        buf: &mut B,
        truncate: impl FnOnce(&mut B, usize),
    ) -> Result<()> {
        decrypt_within!(buf, truncate, |buf, tag| {
            self.decrypt_inout_detached(nonce, aad, buf, tag)
        })
    }

    #[inline]
    fn decrypt_within_with_var_nonce<B: AsMut<[u8]>>(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut B,
        truncate: impl FnOnce(&mut B, usize),
    ) -> Result<()> {
        decrypt_within!(buf, truncate, |buf, tag| {
            self.decrypt_inout_with_var_nonce_detached(nonce, aad, buf, tag)
        })
    }
}
