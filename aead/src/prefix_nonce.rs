use crate::{AeadCore, AeadInOut, Buffer, Error, Nonce, Payload, Result, Tag};
use common::{Key, KeyInit, KeySizeUser, typenum::Unsigned};
use inout::InOutBuf;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "getrandom")]
use common::getrandom::SysRng;
#[cfg(feature = "rand_core")]
use common::{Generate, rand_core::TryCryptoRng};

/// AEAD which uses nonce-prefixed ciphertext messages.
#[derive(Clone, Debug)]
#[repr(transparent)]
pub struct PrefixNonceAead<A> {
    /// Inner AEAD.
    aead: A,
}

impl<A: KeySizeUser> KeySizeUser for PrefixNonceAead<A> {
    type KeySize = A::KeySize;
}

impl<A: KeyInit> KeyInit for PrefixNonceAead<A> {
    fn new(key: &Key<Self>) -> Self {
        Self { aead: A::new(key) }
    }
}

impl<A: AeadInOut> PrefixNonceAead<A> {
    /// Encrypt the given `plaintext` under a randomly generated nonce, returning a byte vector.
    ///
    /// # Errors
    /// TODO
    #[cfg(all(feature = "alloc", feature = "getrandom"))]
    pub fn encrypt_to_vec<'msg, 'aad>(
        &self,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>> {
        let plaintext = plaintext.into();
        let mut out = Vec::with_capacity(
            A::NonceSize::USIZE
                .saturating_add(plaintext.msg.len())
                .saturating_add(A::TagSize::USIZE),
        );
        self.encrypt_to_buffer(plaintext, &mut out)?;
        Ok(out)
    }

    /// Encrypt the given `plaintext` under a randomly generated nonce, writing output to the given
    /// `ciphertext` buffer.
    ///
    /// # Errors
    /// TODO
    #[cfg(feature = "getrandom")]
    pub fn encrypt_to_buffer<'msg, 'aad>(
        &self,
        plaintext: impl Into<Payload<'msg, 'aad>>,
        ciphertext: &mut impl Buffer,
    ) -> Result<()> {
        self.encrypt_with_rng_to_buffer(&mut SysRng, plaintext, ciphertext)
    }

    /// Generate a random nonce from the provided RNG and encrypt the given `plaintext`, writing
    /// output to the given `ciphertext` buffer.
    ///
    /// # Errors
    /// TODO
    #[cfg(feature = "rand_core")]
    pub fn encrypt_with_rng_to_buffer<'msg, 'aad, R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        plaintext: impl Into<Payload<'msg, 'aad>>,
        ciphertext: &mut impl Buffer,
    ) -> Result<()> {
        let nonce = Nonce::<A>::try_generate_from_rng(rng).map_err(|_| Error)?;
        self.encrypt_with_nonce_to_buffer(&nonce, plaintext, ciphertext)
    }

    /// Encrypt the given `plaintext` under the provided `nonce`, prepending it to the `ciphertext`.
    ///
    /// # Errors
    /// TODO
    pub fn encrypt_with_nonce_to_buffer<'msg, 'aad>(
        &self,
        nonce: &Nonce<A>,
        plaintext: impl Into<Payload<'msg, 'aad>>,
        ciphertext: &mut impl Buffer,
    ) -> Result<()> {
        let plaintext = plaintext.into();
        ciphertext.extend_from_slice(nonce)?;
        ciphertext.extend_from_slice(plaintext.msg)?;

        let tag = self.aead.encrypt_inout_detached(
            nonce,
            plaintext.aad,
            (&mut ciphertext.as_mut()[A::NonceSize::USIZE..]).into(),
        )?;

        ciphertext.extend_from_slice(&tag)?;
        Ok(())
    }

    /// Decrypt a [`Buffer`] containing a ciphertext message in-place, leaving the plaintext message
    /// as its contents upon success.
    ///
    /// # Errors
    /// TODO
    pub fn decrypt_in_place(&self, aad: &[u8], buffer: &mut impl Buffer) -> Result<()> {
        let (nonce, buf, tag) = decode_mut_aead_msg::<A>(buffer.as_mut())?;
        let ct_len = buf.len();
        self.aead
            .decrypt_inout_detached(&nonce, aad, buf.into(), &tag)?;

        // Place the decrypted plaintext message at the beginning of the buffer by copying it over
        // the prefix nonce
        let ct_end = A::NonceSize::USIZE.saturating_add(ct_len);
        buffer.as_mut().copy_within(A::NonceSize::USIZE..ct_end, 0);
        buffer.truncate(ct_len);
        Ok(())
    }

    /// Decrypt the provided `ciphertext` message which includes a prepended nonce to the given
    /// byte slice output buffer.
    ///
    /// # Errors
    /// TODO
    pub fn decrypt_to_slice<'msg, 'aad>(
        &self,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
        out: &mut [u8],
    ) -> Result<()> {
        let payload = ciphertext.into();
        let (nonce, ct, tag) = decode_aead_msg::<A>(payload.msg)?;
        let buf = InOutBuf::new(ct, out).map_err(|_| Error)?;
        self.aead
            .decrypt_inout_detached(&nonce, payload.aad, buf, &tag)
    }

    /// Decrypt the provided `ciphertext` message which includes a prepended nonce, returning a byte
    /// vector upon success.
    ///
    /// # Errors
    /// TODO
    #[cfg(feature = "alloc")]
    pub fn decrypt_to_vec<'msg, 'aad>(
        &self,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>> {
        let ciphertext = ciphertext.into();
        let plaintext_len = ciphertext
            .msg
            .len()
            .saturating_sub(A::NonceSize::USIZE)
            .saturating_sub(A::TagSize::USIZE);
        let mut out = vec![0u8; plaintext_len];
        self.decrypt_to_slice(ciphertext, &mut out)?;
        Ok(out)
    }
}

/// Decode an AEAD message from the given byte slice.
fn decode_aead_msg<A: AeadCore>(ciphertext: &[u8]) -> Result<(Nonce<A>, &[u8], Tag<A>)> {
    let (nonce, rest) = ciphertext
        .split_at_checked(A::NonceSize::USIZE)
        .ok_or(Error)?;
    let (ciphertext, tag) = rest.split_at_checked(A::TagSize::USIZE).ok_or(Error)?;
    let nonce = Nonce::<A>::try_from(nonce).map_err(|_| Error)?;
    let tag = Tag::<A>::try_from(tag).map_err(|_| Error)?;
    Ok((nonce, ciphertext, tag))
}

/// Decode an AEAD message from a mutable input buffer, returning the mutable ciphertext message
/// portion for use with in-place encryption.
fn decode_mut_aead_msg<A: AeadCore>(
    ciphertext: &mut [u8],
) -> Result<(Nonce<A>, &mut [u8], Tag<A>)> {
    let (nonce, ct, tag) = decode_aead_msg::<A>(ciphertext)?;
    let ct_len = ct.len();
    Ok((nonce, &mut ciphertext[A::NonceSize::USIZE..][ct_len..], tag))
}
