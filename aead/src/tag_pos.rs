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

/// Trait implemented for AEAD modes which specify tag position in ciphertext.
#[allow(missing_docs, clippy::missing_errors_doc)] // TODO: fix
pub trait AeadWithTag: AeadCore {
    /// The AEAD tag position.
    const TAG_POSITION: TagPosition;

    fn encrypt_into<B: AsMut<[u8]>>(
        &self,
        nonce: &Nonce<Self>,
        aad: &[u8],
        msg: &[u8],
        allocate: impl FnOnce(usize) -> B,
    ) -> Result<B> {
        self.encrypt_into_with_var_nonce(nonce, aad, msg, allocate)
    }

    fn decrypt_into<B: AsMut<[u8]>>(
        &self,
        nonce: &Nonce<Self>,
        aad: &[u8],
        msg: &[u8],
        allocate: impl FnOnce(usize) -> B,
    ) -> Result<B> {
        self.decrypt_into_with_var_nonce(nonce, aad, msg, allocate)
    }

    fn encrypt_into_with_var_nonce<B: AsMut<[u8]>>(
        &self,
        nonce: &[u8],
        aad: &[u8],
        msg: &[u8],
        allocate: impl FnOnce(usize) -> B,
    ) -> Result<B> {
        let tag_len = Self::TagSize::USIZE;
        let ct_tag_len = msg.len().checked_add(tag_len).ok_or(Error)?;
        let mut ct_tag = allocate(ct_tag_len);
        assert_eq!(ct_tag.as_mut().len(), ct_tag_len);

        let (ct_dst, tag_dst) = match Self::TAG_POSITION {
            TagPosition::Postfix => ct_tag.as_mut().split_at_mut(msg.len()),
            TagPosition::Prefix => {
                let (tag_dst, ct_dst) = ct_tag.as_mut().split_at_mut(tag_len);
                (ct_dst, tag_dst)
            }
        };

        let buf = InOutBuf::new(msg, ct_dst).expect("`msg` and `ct_dst` have the same length");
        let tag = self.encrypt_inout_with_var_nonce_detached(nonce, aad, buf)?;
        tag_dst.copy_from_slice(&tag);

        Ok(ct_tag)
    }

    fn decrypt_into_with_var_nonce<B: AsMut<[u8]>>(
        &self,
        nonce: &[u8],
        aad: &[u8],
        msg: &[u8],
        allocate: impl FnOnce(usize) -> B,
    ) -> Result<B> {
        let tag_len = Self::TagSize::USIZE;
        let ct_len = msg.len().checked_sub(tag_len).ok_or(Error)?;

        let (ct, tag) = match Self::TAG_POSITION {
            TagPosition::Postfix => msg.split_at(ct_len),
            TagPosition::Prefix => {
                let (tag, ct) = msg.split_at(tag_len);
                (ct, tag)
            }
        };

        let tag = tag.try_into().expect("`tag` has correct length");
        let mut pt_dst = allocate(ct_len);
        let buf = InOutBuf::new(ct, pt_dst.as_mut())
            .expect("`ct` and `pt_dst` should have the same length");
        self.decrypt_inout_with_var_nonce_detached(nonce, aad, buf, tag)?;

        Ok(pt_dst)
    }

    fn encrypt_within<B: AsMut<[u8]>>(
        &self,
        nonce: &Nonce<Self>,
        aad: &[u8],
        buf: &mut B,
        extend: impl FnOnce(&mut B, usize),
    ) -> Result<()> {
        self.encrypt_within_with_var_nonce(nonce, aad, buf, extend)
    }

    fn decrypt_within<B: AsMut<[u8]>>(
        &self,
        nonce: &Nonce<Self>,
        aad: &[u8],
        buf: &mut B,
        truncate: impl FnOnce(&mut B, usize),
    ) -> Result<()> {
        self.decrypt_within_with_var_nonce(nonce, aad, buf, truncate)
    }

    fn encrypt_within_with_var_nonce<B: AsMut<[u8]>>(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut B,
        extend: impl FnOnce(&mut B, usize),
    ) -> Result<()> {
        let tag_len = Self::TagSize::USIZE;
        let pt_len = buf.as_mut().len();
        let ct_len = pt_len.checked_add(tag_len).ok_or(Error)?;

        extend(buf, ct_len);
        assert_eq!(buf.as_mut().len(), ct_len);

        let (msg, tag_dst) = match Self::TAG_POSITION {
            TagPosition::Postfix => buf.as_mut().split_at_mut(pt_len),
            TagPosition::Prefix => {
                buf.as_mut().copy_within(..pt_len, tag_len);
                let (tag_dst, ct_dst) = buf.as_mut().split_at_mut(tag_len);
                (ct_dst, tag_dst)
            }
        };

        let buf = InOutBuf::from(msg);
        let tag = self.encrypt_inout_with_var_nonce_detached(nonce, aad, buf)?;
        tag_dst.copy_from_slice(&tag);

        Ok(())
    }

    fn decrypt_within_with_var_nonce<B: AsMut<[u8]>>(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut B,
        truncate: impl FnOnce(&mut B, usize),
    ) -> Result<()> {
        let tag_len = Self::TagSize::USIZE;
        let ct_len = buf.as_mut().len().checked_sub(tag_len).ok_or(Error)?;

        let (ct, tag) = match Self::TAG_POSITION {
            TagPosition::Postfix => buf.as_mut().split_at_mut(ct_len),
            TagPosition::Prefix => {
                let (tag, ct) = buf.as_mut().split_at_mut(tag_len);
                (ct, tag)
            }
        };

        let tag = (&*tag).try_into().expect("`tag` has correct length");
        self.decrypt_inout_with_var_nonce_detached(nonce, aad, ct.into(), tag)?;

        if Self::TAG_POSITION == TagPosition::Prefix {
            buf.as_mut().copy_within(tag_len.., 0);
        }

        truncate(buf, ct_len);
        assert_eq!(buf.as_mut().len(), ct_len);

        Ok(())
    }
}
