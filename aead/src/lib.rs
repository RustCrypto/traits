#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
// #![forbid(unsafe_code)]
#![warn(
    clippy::unwrap_used,
    // missing_docs,
    rust_2018_idioms,
    missing_debug_implementations
)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "bytes")]
use bytes::BytesMut;

#[cfg(feature = "arrayvec")]
use arrayvec::ArrayVec;

#[cfg(feature = "dev")]
pub mod dev;

mod dyn_aead;

pub use dyn_aead::DynAead;

pub mod stream;

pub use crypto_common::{
    self,
    array::{self, typenum::consts},
    Key, KeyInit, KeySizeUser,
};

#[cfg(feature = "rand_core")]
pub use crypto_common::rand_core;
use inout::{InOutBuf, InOutBufReserved};

use core::fmt;
use crypto_common::array::{typenum::Unsigned, Array, ArraySize};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "getrandom")]
use crypto_common::getrandom;
#[cfg(feature = "rand_core")]
use rand_core::CryptoRngCore;

/// Nonce: single-use value for ensuring ciphertexts are unique
pub type Nonce<A> = Array<u8, <A as Aead>::NonceSize>;

/// Tag: authentication code which ensures ciphertexts are authentic
pub type Tag<A> = Array<u8, <A as Aead>::TagSize>;

/// Authenticated Encryption with Associated Data (AEAD) error type.
///
/// This type is deliberately opaque as to avoid potential side-channel
/// leakage (e.g. padding oracle).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Error;

/// Result type alias with [`Error`].
pub type Result<T> = core::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("aead::Error")
    }
}

impl core::error::Error for Error {}

/// Authenticated Encryption with Associated Data (AEAD) algorithm trait.
pub trait Aead {
    /// The length of a nonce.
    type NonceSize: ArraySize;

    /// The length of a tag.
    type TagSize: ArraySize;

    /// Constant which defines whether AEAD specification appends or prepends tags.
    ///
    /// It influences the behavior of the [`Aead::encrypt_to_vec`], [`Aead::decrypt_to_vec`],
    /// [`Aead::encrypt_to_buffer`], and [`Aead::decrypt_to_buffer`] methods.
    ///
    /// If the specification does not explicitly specify tag kind, we default to postfix tags.
    const IS_POSTFIX: bool = true;

    /// Encrypt the [`InOutBuf`] data, returning the authentication tag.
    fn detached_encrypt_inout(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag<Self>>;

    /// Decrypt the [`InOutBuf`] data, returning an error in the event the provided
    /// authentication tag does not match the given ciphertext.
    fn detached_decrypt_inout(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag<Self>,
    ) -> Result<()>;

    /// Encrypt the data in-place, returning the authentication tag.
    #[inline]
    fn detached_encrypt_inplace(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<Self>> {
        self.detached_encrypt_inout(nonce, associated_data, buffer.into())
    }

    /// Encrypt the data in-place, returning an error in the event the provided
    /// authentication tag does not match the given ciphertext.
    #[inline]
    fn detached_decrypt_inplace(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self>,
    ) -> Result<()> {
        self.detached_decrypt_inout(nonce, associated_data, buffer.into(), tag)
    }

    /// Encrypt the data buffer-to-buffer, returning the authentication tag.
    #[inline]
    fn detached_encrypt_to_buf(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<Tag<Self>> {
        let buf = InOutBuf::new(src, dst).map_err(|_| Error)?;
        self.detached_encrypt_inout(nonce, associated_data, buf)
    }

    /// Encrypt the data buffer-to-buffer, returning an error in the event the provided
    /// authentication tag does not match the given ciphertext.
    #[inline]
    fn detached_decrypt_to_buf(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        src: &[u8],
        dst: &mut [u8],
        tag: &Tag<Self>,
    ) -> Result<()> {
        let buf = InOutBuf::new(src, dst).map_err(|_| Error)?;
        self.detached_decrypt_inout(nonce, associated_data, buf, tag)
    }

    /// Encrypt the [`InOutBufReserved`] data, append the authentication tag, and return
    /// the resulting byte slice.
    ///
    /// `buffer` should have at least [`TagSize`][Aead::TagSize] bytes of additional output
    /// capacity; otherwise, the method will return an error.
    ///
    /// The returned byte slice is guaranteed to point to the output of `buffer`.
    #[inline]
    fn postfix_encrypt_inout<'out>(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        mut buffer: InOutBufReserved<'_, 'out, u8>,
    ) -> Result<&'out mut [u8]> {
        let (msg, tail) = split_reserved(&mut buffer);
        let tag_len = Self::TagSize::USIZE;
        let tag_dst = tail.get_mut(..tag_len).ok_or(Error)?;
        let res_len = msg.len() + tag_len;
        let tag = self.detached_encrypt_inout(nonce, associated_data, msg)?;
        tag_dst.copy_from_slice(&tag);

        let out_buf = into_out_buf2(buffer);
        Ok(&mut out_buf[..res_len])
    }

    /// Decrypt the [`InOutBuf`] data, verify the appended authentication tag, and return
    /// the resulting byte slice in case of success.
    ///
    /// Returns an error if the provided authentication tag does not match the given ciphertext
    /// or if the size of `buffer` is smaller than the tag size.
    ///
    /// The returned byte slice is guaranteed to point to the output of `buffer`.
    #[inline]
    fn postfix_decrypt_inout<'out>(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, 'out, u8>,
    ) -> Result<&'out mut [u8]> {
        let tag_len = Self::TagSize::USIZE;
        let ct_len = buffer.len().checked_sub(tag_len).ok_or(Error)?;
        let (mut buf, tag) = buffer.split_at(ct_len);
        let tag = tag.get_in().try_into().expect("tag has correct length");
        self.detached_decrypt_inout(nonce, associated_data, buf.reborrow(), tag)?;
        Ok(into_out_buf(buf))
    }

    /// Encrypt the plaintext data of length `plaintext_len` residing at the beggining of `buffer`
    /// in-place, append the authentication tag, and return the resulting byte slice.
    ///
    /// `buffer` should have at least [`TagSize`][Aead::TagSize] bytes of additional output
    /// capacity; otherwise, the method will return an error.
    ///
    /// The returned byte slice is guaranteed to point to `buffer`.
    #[inline]
    fn postfix_encrypt_inplace<'out>(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &'out mut [u8],
        plaintext_len: usize,
    ) -> Result<&'out mut [u8]> {
        let tag_len = Self::TagSize::USIZE;
        let res_len = plaintext_len + tag_len;
        let buf = buffer.get_mut(..res_len).ok_or(Error)?;
        let (msg, tag_dst) = buf.split_at_mut(plaintext_len);
        let tag = self.detached_encrypt_inout(nonce, associated_data, msg.into())?;
        tag_dst.copy_from_slice(&tag);
        Ok(buf)
    }

    /// Decrypt the data in `buffer` in-place, verify the appended authentication tag, and return
    /// the resulting byte slice in case of success.
    ///
    /// Returns an error if the provided authentication tag does not match the given ciphertext
    /// or if the size of `buffer` is smaller than the tag size.
    ///
    /// The returned byte slice is guaranteed to point to the output of `buffer`.
    #[inline]
    fn postfix_decrypt_inplace<'out>(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &'out mut [u8],
    ) -> Result<&'out mut [u8]> {
        let tag_len = Self::TagSize::USIZE;
        let ct_len = buffer.len().checked_sub(tag_len).ok_or(Error)?;
        let (buf, tag) = buffer.split_at_mut(ct_len);
        let tag = (&*tag).try_into().expect("tag has correct length");
        self.detached_decrypt_inout(nonce, associated_data, buf.into(), tag)?;
        Ok(buf)
    }

    /// Encrypt the data in `plaintext`, write resulting ciphertext to `buffer`, append
    /// the authentication tag, and return the resulting byte slice.
    ///
    /// `buffer` should have at least [`TagSize`][Aead::TagSize] bytes of additional capacity;
    /// otherwise, the method will return an error.
    ///
    /// The returned byte slice is guaranteed to point to the output of `buffer`.
    #[inline]
    fn postfix_encrypt_to_buf<'out>(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        plaintext: &[u8],
        buffer: &'out mut [u8],
    ) -> Result<&'out mut [u8]> {
        let tag_len = Self::TagSize::USIZE;
        let res_len = plaintext.len() + tag_len;
        let buf = buffer.get_mut(..res_len).ok_or(Error)?;
        let (msg_dst, tag_dst) = buf.split_at_mut(plaintext.len());
        let inout_buf = InOutBuf::new(plaintext, msg_dst).expect("ct_dst has correct length");
        let tag = self.detached_encrypt_inout(nonce, associated_data, inout_buf)?;
        tag_dst.copy_from_slice(&tag);
        Ok(buf)
    }

    /// Decrypt the data in `ciphertext`, write resulting ciphertext to `buffer`, verify
    /// the appended authentication tag, and return the resulting byte slice in case of success.
    ///
    /// Returns an error if the provided authentication tag does not match the given ciphertext,
    /// if the size of `ciphertext` is smaller than the tag size, or if the size of `buffer` is
    /// too small for resulting plaintext (i.e. it should have capacity of at least
    /// `ciphertext.len() - tag_size`).
    ///
    /// The returned byte slice is guaranteed to point to the output of `buffer`.
    #[inline]
    fn postfix_decrypt_to_buf<'out>(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        ciphertext: &[u8],
        buffer: &'out mut [u8],
    ) -> Result<&'out mut [u8]> {
        let tag_len = Self::TagSize::USIZE;
        let pt_len = ciphertext.len().checked_sub(tag_len).ok_or(Error)?;
        let pt_dst = buffer.get_mut(..pt_len).ok_or(Error)?;
        let (ct, tag) = ciphertext.split_at(pt_len);
        let tag = tag.try_into().expect("tag has correct length");
        let buf = InOutBuf::new(ct, pt_dst).expect("buffers have the same length");
        self.detached_decrypt_inout(nonce, associated_data, buf, tag)?;
        Ok(pt_dst)
    }

    /// Encrypt the data in `buffer`, and append the authentication tag to it.
    ///
    /// `buffer` is a generic [`Buffer`] type. See the trait docs for more information.
    #[inline]
    fn postfix_encrypt_buffer(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut impl Buffer,
    ) -> Result<()> {
        let tag = self.detached_encrypt_inplace(nonce, associated_data, buffer.as_mut())?;
        buffer.extend_from_slice(&tag)
    }

    /// Decrypt the data in `buffer`, verify the appended authentication tag, and truncate `buffer`
    /// to contain only the resulting plaintext.
    ///
    /// Returns an error if the provided authentication tag does not match the given ciphertext,
    /// or if the length of `buffer` is smaller than the tag size.
    #[inline]
    fn postfix_decrypt_buffer(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut impl Buffer,
    ) -> Result<()> {
        let pt = self.postfix_decrypt_inplace(nonce, associated_data, buffer.as_mut())?;
        let pt_len = pt.len();
        buffer.truncate(pt_len);
        Ok(())
    }

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
    #[cfg(feature = "alloc")]
    #[inline]
    fn encrypt_to_vec<'msg, 'aad>(
        &self,
        nonce: &Nonce<Self>,
        pt_payload: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.encrypt_to_buffer(nonce, pt_payload, &mut buf)?;
        Ok(buf)
    }

    /// Decrypt the given ciphertext slice, and return the resulting plaintext
    /// as a vector of bytes.
    ///
    /// See notes on [`Aead::encrypt_to_vec()`] about allowable message payloads and
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
    #[cfg(feature = "alloc")]
    #[inline]
    fn decrypt_to_vec<'msg, 'aad>(
        &self,
        nonce: &Nonce<Self>,
        ct_payload: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.decrypt_to_buffer(nonce, ct_payload, &mut buf)?;
        Ok(buf)
    }

    #[inline]
    fn encrypt_to_buffer<'msg, 'aad, B: Buffer + ?Sized>(
        &self,
        nonce: &Nonce<Self>,
        pt_payload: impl Into<Payload<'msg, 'aad>>,
        buffer: &mut B,
    ) -> Result<()> {
        let Payload { msg: pt, aad } = pt_payload.into();
        let tag_len = Self::TagSize::USIZE;
        buffer.resize(pt.len() + tag_len)?;
        let (ct_dst, tag_dst) = if Self::IS_POSTFIX {
            buffer.as_mut().split_at_mut(pt.len())
        } else {
            buffer.as_mut().split_at_mut(tag_len)
        };
        let tag = self.detached_encrypt_to_buf(nonce, aad, pt, ct_dst)?;
        tag_dst.copy_from_slice(&tag);
        Ok(())
    }

    #[inline]
    fn decrypt_to_buffer<'msg, 'aad, B: Buffer + ?Sized>(
        &self,
        nonce: &Nonce<Self>,
        ct_payload: impl Into<Payload<'msg, 'aad>>,
        buffer: &mut B,
    ) -> Result<()> {
        let Payload { msg: ct_tag, aad } = ct_payload.into();
        let tag_len = Self::TagSize::USIZE;
        let pt_len = ct_tag.len().checked_sub(tag_len).ok_or(Error)?;
        buffer.resize(pt_len)?;
        let (ct, tag) = if Self::IS_POSTFIX {
            ct_tag.split_at(pt_len)
        } else {
            ct_tag.split_at(tag_len)
        };
        let tag = tag.try_into().expect("tag has correct length");
        self.detached_decrypt_to_buf(nonce, aad, ct, buffer.as_mut(), tag)?;
        Ok(())
    }

    /// Generate a random nonce for this AEAD algorithm.
    ///
    /// See the crate-level documentation for requirements for random nonces.
    #[cfg(feature = "getrandom")]
    fn generate_nonce() -> core::result::Result<Nonce<Self>, getrandom::Error> {
        let mut nonce = Nonce::<Self>::default();
        getrandom::getrandom(&mut nonce)?;
        Ok(nonce)
    }

    /// Generate a random nonce for this AEAD algorithm using the specified [`CryptoRngCore`].
    ///
    /// See the crate-level documentation for requirements for random nonces.
    #[cfg(feature = "rand_core")]
    fn generate_nonce_with_rng(
        rng: &mut impl CryptoRngCore,
    ) -> core::result::Result<Nonce<Self>, rand_core::Error> {
        let mut nonce = Nonce::<Self>::default();
        rng.try_fill_bytes(&mut nonce)?;
        Ok(nonce)
    }
}

// TODO: move to `inout`
fn split_reserved<'a>(
    buf: &'a mut InOutBufReserved<'_, '_, u8>,
) -> (InOutBuf<'a, 'a, u8>, &'a mut [u8]) {
    let in_len = buf.get_in_len();
    let out_len = buf.get_out_len();
    let in_ptr = buf.get_in().as_ptr();
    let out_ptr = buf.get_out().as_mut_ptr();
    unsafe {
        let body = InOutBuf::from_raw(in_ptr, out_ptr, in_len);
        let tail = core::slice::from_raw_parts_mut(out_ptr.add(in_len), out_len - in_len);
        (body, tail)
    }
}

fn into_out_buf<'out>(buf: InOutBuf<'_, 'out, u8>) -> &'out mut [u8] {
    let out_len = buf.len();
    let (_, out_ptr) = buf.into_raw();
    unsafe { core::slice::from_raw_parts_mut(out_ptr, out_len) }
}

fn into_out_buf2<'out>(buf: InOutBufReserved<'_, 'out, u8>) -> &'out mut [u8] {
    let out_len = buf.get_out_len();
    let (_, out_ptr) = buf.into_raw();
    unsafe { core::slice::from_raw_parts_mut(out_ptr, out_len) }
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

#[cfg(feature = "alloc")]
impl<'msg> From<&'msg [u8]> for Payload<'msg, '_> {
    #[inline]
    fn from(msg: &'msg [u8]) -> Self {
        Self { msg, aad: b"" }
    }
}

/// In-place encryption/decryption byte buffers.
///
/// This trait defines the set of methods needed to support in-place operations
/// on a `Vec`-like data type.
pub trait Buffer: AsMut<[u8]> {
    /// Resizes buffer to the requested length.
    ///
    /// If buffer is smaller than `len`, fills it with zeros. Otherwise, truncates it to `len`.
    fn resize(&mut self, len: usize) -> Result<()>;

    /// Extend this buffer from the given slice
    fn extend_from_slice(&mut self, other: &[u8]) -> Result<()>;

    /// Truncate this buffer to the given size
    fn truncate(&mut self, len: usize);
}

#[cfg(feature = "alloc")]
impl Buffer for Vec<u8> {
    fn resize(&mut self, len: usize) -> Result<()> {
        Vec::resize(self, len, 0);
        Ok(())
    }

    fn extend_from_slice(&mut self, other: &[u8]) -> Result<()> {
        Vec::extend_from_slice(self, other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        Vec::truncate(self, len);
    }
}

#[cfg(feature = "bytes")]
impl Buffer for BytesMut {
    fn resize(&mut self, len: usize) -> Result<()> {
        BytesMut::resize(self, len, 0);
        Ok(())
    }

    fn extend_from_slice(&mut self, other: &[u8]) -> Result<()> {
        BytesMut::extend_from_slice(self, other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        BytesMut::truncate(self, len);
    }
}

#[cfg(feature = "arrayvec")]
impl<const N: usize> Buffer for ArrayVec<u8, N> {
    fn resize(&mut self, len: usize) -> Result<()> {
        if let Some(ext_len) = len.checked_sub(self.len()) {
            let buf = &[0u8; N][..ext_len];
            self.try_extend_from_slice(buf).map_err(|_| Error)
        } else {
            self.truncate(len);
            Ok(())
        }
    }

    fn extend_from_slice(&mut self, other: &[u8]) -> Result<()> {
        ArrayVec::try_extend_from_slice(self, other).map_err(|_| Error)
    }

    fn truncate(&mut self, len: usize) {
        ArrayVec::truncate(self, len);
    }
}

#[cfg(feature = "heapless")]
impl<const N: usize> Buffer for heapless::Vec<u8, N> {
    fn resize(&mut self, len: usize) -> Result<()> {
        heapless::Vec::resize(self, len, 0).map_err(|_| Error)
    }

    fn extend_from_slice(&mut self, other: &[u8]) -> Result<()> {
        heapless::Vec::extend_from_slice(self, other).map_err(|_| Error)
    }

    fn truncate(&mut self, len: usize) {
        heapless::Vec::truncate(self, len);
    }
}
