use crate::{
    AeadCore, AeadTagPosition, Error, InOutBuf, Nonce, Result,
    TagPosition::{Postfix, Prefix},
};
use alloc::vec::Vec;
use common::array::typenum::Unsigned;

/// High-level functionality of Authenticated Encryption with Associated Data (AEAD) algorithms.
pub trait Aead: AeadCore + AeadTagPosition {
    /// Encrypt the given plaintext payload, and return the resulting
    /// ciphertext as a vector of bytes.
    ///
    /// The [`Payload`] type can be used to provide Additional Associated Data
    /// (AAD) along with the message: this is an optional bytestring which is
    /// not encrypted, but *is* authenticated along with the message. Failure
    /// to pass the same AAD that was used during encryption will cause
    /// decryption to fail, which is useful if you would like to "bind" the
    /// ciphertext to some other identifier, like a digital signature key
    /// or other identifier.
    ///
    /// If you don't care about AAD and just want to encrypt a plaintext
    /// message, `&[u8]` will automatically be coerced into a `Payload`:
    ///
    /// ```nobuild
    /// let plaintext = b"Top secret message, handle with care";
    /// let ciphertext = cipher.encrypt(nonce, plaintext);
    /// ```
    ///
    /// The default implementation assumes a postfix tag (ala AES-GCM,
    /// AES-GCM-SIV, ChaCha20Poly1305). [`Aead`] implementations which do not
    /// use a postfix tag will need to override this to correctly assemble the
    /// ciphertext message.
    ///
    /// # Errors
    /// AEAD algorithm implementations may return an error if the plaintext or AAD are too long.
    fn encrypt<'msg, 'aad>(
        &self,
        nonce: &Nonce<Self>,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>>;

    /// Decrypt the given ciphertext slice, and return the resulting plaintext
    /// as a vector of bytes.
    ///
    /// See notes on [`Aead::encrypt()`] about allowable message payloads and
    /// Associated Additional Data (AAD).
    ///
    /// If you have no AAD, you can call this as follows:
    ///
    /// ```nobuild
    /// let ciphertext = b"...";
    /// let plaintext = cipher.decrypt(nonce, ciphertext)?;
    /// ```
    ///
    /// The default implementation assumes a postfix tag (ala AES-GCM,
    /// AES-GCM-SIV, ChaCha20Poly1305). [`Aead`] implementations which do not
    /// use a postfix tag will need to override this to correctly parse the
    /// ciphertext message.
    ///
    /// # Errors
    /// - if the `ciphertext` is inauthentic (i.e. tag verification failure)
    /// - if the `ciphertext` is too long
    /// - if the `aad` is too long
    fn decrypt<'msg, 'aad>(
        &self,
        nonce: &Nonce<Self>,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>>;
}

impl<T: AeadCore + AeadTagPosition> Aead for T {
    #[allow(clippy::unwrap_in_result)]
    fn encrypt<'msg, 'aad>(
        &self,
        nonce: &Nonce<Self>,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>> {
        let Payload { msg: pt, aad } = plaintext.into();

        let tag_len = Self::TagSize::USIZE;
        let ct_len = pt.len().checked_add(tag_len).ok_or(Error)?;
        let mut buffer = alloc::vec![0u8; ct_len];

        let (ct_dst, tag_dst) = match Self::TAG_POSITION {
            Postfix => buffer.split_at_mut(pt.len()),
            Prefix => {
                let (tag_dst, ct_dst) = buffer.split_at_mut(tag_len);
                (ct_dst, tag_dst)
            }
        };

        let buf = InOutBuf::new(pt, ct_dst).expect("`pt` and `ct_dst` have the same length");
        let tag = self.encrypt_inout_detached(nonce, aad, buf)?;
        tag_dst.copy_from_slice(&tag);

        Ok(buffer)
    }

    #[allow(clippy::unwrap_in_result)]
    fn decrypt<'msg, 'aad>(
        &self,
        nonce: &Nonce<Self>,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>> {
        let Payload { msg: ct_tag, aad } = ciphertext.into();

        let tag_len = Self::TagSize::USIZE;
        let ct_len = ct_tag.len().checked_sub(tag_len).ok_or(Error)?;

        let (ct, tag) = match Self::TAG_POSITION {
            Postfix => ct_tag.split_at(ct_len),
            Prefix => {
                let (tag, ct) = ct_tag.split_at(tag_len);
                (ct, tag)
            }
        };

        let tag = tag.try_into().expect("`tag` has correct length");
        let mut pt_dst = alloc::vec![0u8; ct_len];
        let buf = InOutBuf::new(ct, &mut pt_dst).expect("`ct` and `pt_dst` have the same length");
        self.decrypt_inout_detached(nonce, aad, buf, tag)?;

        Ok(pt_dst)
    }
}

/// AEAD payloads (message + AAD).
///
/// Combination of a message (plaintext or ciphertext) and
/// "additional associated data" (AAD) to be authenticated (in cleartext)
/// along with the message.
///
/// If you don't care about AAD, you can pass a `&[u8]` as the payload to
/// `encrypt`/`decrypt` and it will automatically be coerced to this type.
#[derive(Debug)]
pub struct Payload<'msg, 'aad> {
    /// Message to be encrypted/decrypted
    pub msg: &'msg [u8],

    /// Optional "additional associated data" to authenticate along with
    /// this message. If AAD is provided at the time the message is encrypted,
    /// the same AAD *MUST* be provided at the time the message is decrypted,
    /// or decryption will fail.
    pub aad: &'aad [u8],
}

impl<'msg> From<&'msg [u8]> for Payload<'msg, '_> {
    fn from(msg: &'msg [u8]) -> Self {
        Self { msg, aad: b"" }
    }
}
