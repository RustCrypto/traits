#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "dev")]
pub mod dev;

#[cfg(feature = "alloc")]
mod aead;
#[cfg(feature = "alloc")]
pub use aead::Aead;

mod variable;

pub use variable::VariableAead;

#[cfg(feature = "rand_core")]
pub use common::{Generate, rand_core};
pub use inout;

pub use common::{
    self, Key, KeyInit, KeySizeUser,
    array::{self, typenum::consts},
};
pub use inout::InOutBuf;

use TagPosition::{Postfix, Prefix};
use array::{Array, ArraySize};
use common::typenum::Unsigned;
use core::fmt;

/// Nonce: single-use value for ensuring ciphertexts are unique.
///
/// AEAD algorithms accept a parameter to encryption/decryption called
/// a "nonce" which must be unique every time encryption is performed and
/// never repeated for the same key. The nonce is often prepended to the
/// ciphertext, a.k.a. an explicit nonce, but may also be an implicit counter.
///
/// AEAD decryption takes the nonce which was originally used to produce a
/// given ciphertext as a parameter along with the ciphertext itself.
///
/// # Generating random nonces
///
/// Nonces don't necessarily have to be random, but it is a simple strategy
/// which can be implemented as follows using the [`Generate`] trait
/// (requires `getrandom` feature):
///
/// ```text
/// use aead::{Nonce, Generate};
///
/// let nonce = Nonce::<AeadAlg>::generate();
/// ```
///
/// <div class="warning">
/// AEAD algorithms often fail catastrophically if nonces are ever repeated
/// (with SIV modes being an exception).
///
/// Using random nonces runs the risk of repeating them unless the nonce
/// size is particularly large, e.g. 192-bit extended nonces used by the
/// `XChaCha20Poly1305` and `XSalsa20Poly1305` constructions.
///
/// [NIST SP 800-38D] recommends the following:
///
/// > The total number of invocations of the authenticated encryption
/// > function shall not exceed 2<sup>32</sup>, including all IV lengths and all
/// > instances of the authenticated encryption function with the given key.
///
/// Following this guideline, only 4,294,967,296 messages with random
/// nonces can be encrypted under a given key. While this bound is high,
/// it's possible to encounter in practice, and systems which might
/// reach it should consider alternatives to purely random nonces, like
/// a counter or a combination of a random nonce + counter.
///
/// See the [`aead-stream`] crate for a ready-made implementation of the latter.
/// </div>
///
/// [NIST SP 800-38D]: https://csrc.nist.gov/publications/detail/sp/800-38d/final
/// [`aead-stream`]: https://docs.rs/aead-stream
pub type Nonce<A> = Array<u8, <A as AeadCore>::NonceSize>;

/// Tag: authentication code which ensures ciphertexts are authentic
pub type Tag<A> = Array<u8, <A as AeadCore>::TagSize>;

/// Low-level functionality of Authenticated Encryption with Associated Data (AEAD) algorithms.
pub trait AeadCore {
    /// The nonce length in bytes.
    type NonceSize: ArraySize;

    /// The tag length in bytes.
    type TagSize: ArraySize;

    /// The recommended tag position (postfix or prefix) in resulting ciphertexts.
    ///
    /// If tag position is not explicitly specified, we use postfix tags by default.
    const TAG_POSITION: TagPosition;

    /// Encrypts the plaintext in the input buffer (i.e. `buf.get_in()`),
    /// writes the resulting plaintext into the output buffer (i.e. `buf.get_out()`),
    /// and returns the associated authentication tag.
    ///
    /// On error, the contents of the output buffer are zeroized.
    ///
    /// # Errors
    /// AEAD algorithm implementations may return an error if the plaintext or AAD are too long.
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        aad: &[u8],
        buf: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag<Self>>;

    /// Verifies the authenticity of the ciphertext in the input buffer (i.e. `buf.get_in()`)
    /// using the provided `tag`, and on success decrypts it, writing the resulting plaintext
    /// into the output buffer (i.e. `buf.get_out()`).
    ///
    /// On error, contents of the output buffer are zeroized.
    ///
    /// # Errors
    /// - if the `ciphertext` is inauthentic (i.e. tag verification failure)
    /// - if the `ciphertext` is too long
    /// - if the `aad` is too long
    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        aad: &[u8],
        buf: InOutBuf<'_, '_, u8>,
        tag: &Tag<Self>,
    ) -> Result<()>;

    /// Encrypts the plaintext in `buf` in-place, replacing it with the resulting ciphertext,
    /// and returns the associated authentication tag.
    ///
    /// # Errors
    /// AEAD algorithm implementations may return an error if the plaintext or AAD are too long.
    #[inline]
    fn encrypt_detached(
        &self,
        nonce: &Nonce<Self>,
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<Tag<Self>> {
        self.encrypt_inout_detached(nonce, aad, buf.into())
    }

    /// Verifies the authenticity of the ciphertext in `buf` using the provided `tag`,
    /// and on success decrypts in-place, replacing the ciphertext with the resulting plaintext.
    ///
    /// On error, the contents of `buf` are zeroized.
    ///
    /// # Errors
    /// - if the `ciphertext` is inauthentic (i.e. tag verification failure)
    /// - if the `ciphertext` is too long
    /// - if the `aad` is too long
    #[inline]
    fn decrypt_detached(
        &self,
        nonce: &Nonce<Self>,
        aad: &[u8],
        buf: &mut [u8],
        tag: &Tag<Self>,
    ) -> Result<()> {
        self.decrypt_inout_detached(nonce, aad, buf.into(), tag)
    }

    /// Encrypts `plaintext` into a buffer allocated with `allocate`.
    ///
    /// # Errors
    /// AEAD algorithm implementations may return an error if the plaintext or AAD are too long.
    ///
    /// # Panics
    /// If `allocate` returns a buffer with length in bytes not equal to the provided argument.
    #[inline]
    fn encrypt_into<B: AsMut<[u8]>>(
        &self,
        nonce: &Nonce<Self>,
        aad: &[u8],
        plaintext: &[u8],
        allocate: impl FnOnce(usize) -> B,
    ) -> Result<B> {
        let tag_len = Self::TagSize::USIZE;
        let ct_len = plaintext.len().checked_add(tag_len).ok_or(Error)?;

        let mut ct_tag = allocate(ct_len);
        assert_eq!(
            ct_tag.as_mut().len(),
            ct_len,
            "`allocate` function did not allocate a buffer with the requested size",
        );

        let (ct_dst, tag_dst) = match Self::TAG_POSITION {
            Postfix => ct_tag.as_mut().split_at_mut(plaintext.len()),
            Prefix => {
                let (tag_dst, ct_dst) = ct_tag.as_mut().split_at_mut(tag_len);
                (ct_dst, tag_dst)
            }
        };

        let buf = InOutBuf::new(plaintext, ct_dst)
            .expect("`plaintext` and `ct_dst` always have the same length");
        let tag = self.encrypt_inout_detached(nonce, aad, buf)?;
        tag_dst.copy_from_slice(&tag);

        Ok(ct_tag)
    }

    /// Decrypts `ciphertext` into a buffer allocated with `allocate`.
    ///
    /// # Errors
    /// - if the `ciphertext` is inauthentic (i.e. tag verification failure)
    /// - if the `ciphertext` is too long
    /// - if the `aad` is too long
    ///
    /// # Panics
    /// If `allocate` returns a buffer with length in bytes not equal to the provided argument.
    #[inline]
    fn decrypt_into<B: AsMut<[u8]>>(
        &self,
        nonce: &Nonce<Self>,
        aad: &[u8],
        ciphertext: &[u8],
        allocate: impl FnOnce(usize) -> B,
    ) -> Result<B> {
        let tag_size = Self::TagSize::USIZE;
        let pt_len = ciphertext.len().checked_sub(tag_size).ok_or(Error)?;

        let (ct, tag) = match Self::TAG_POSITION {
            Postfix => ciphertext.split_at(pt_len),
            Prefix => {
                let (tag, ct) = ciphertext.split_at(tag_size);
                (ct, tag)
            }
        };

        let mut pt_dst = allocate(pt_len);
        assert_eq!(
            pt_dst.as_mut().len(),
            pt_len,
            "`allocate` function did not allocate a buffer with the requested size",
        );

        let tag = tag.try_into().expect("`tag` has correct length");
        let buf = InOutBuf::new(ct, pt_dst.as_mut())
            .expect("`ct` and `pt_dst` should always have the same length");
        self.decrypt_inout_detached(nonce, aad, buf, tag)?;

        Ok(pt_dst)
    }

    /// Encrypts the data in `buf`, extending the buffer with `extend`.
    ///
    /// On error, the contents of `buf` are zeroized, but note that it's length may change.
    ///
    /// # Errors
    /// AEAD algorithm implementations may return an error if the plaintext or AAD are too long.
    ///
    /// # Panics
    /// If `extend` does not extend the buffer to the specified length in bytes.
    #[inline]
    fn encrypt_within<B: AsMut<[u8]>>(
        &self,
        nonce: &Nonce<Self>,
        aad: &[u8],
        buf: &mut B,
        extend: impl FnOnce(&mut B, usize),
    ) -> Result<()> {
        let tag_size = Self::TagSize::USIZE;
        let pt_len = buf.as_mut().len();
        let ct_len = pt_len.checked_add(tag_size).ok_or(Error)?;

        extend(buf, ct_len);
        let buf = buf.as_mut();
        assert_eq!(
            buf.len(),
            ct_len,
            "`extend` function did not extend the buffer to the requested size",
        );

        let (pt, tag_dst) = match Self::TAG_POSITION {
            Postfix => buf.split_at_mut(pt_len),
            Prefix => {
                buf.copy_within(..pt_len, tag_size);
                let (tag_dst, pt) = buf.split_at_mut(tag_size);
                (pt, tag_dst)
            }
        };

        self.encrypt_detached(nonce, aad, pt)
            .map(|tag| tag_dst.copy_from_slice(&tag))
            // On failure the `pt` part should be zeroized by the encrypt function
            .inspect_err(|_| tag_dst.fill(0))
    }

    /// Decrypts the data in `buf`, truncating the buffer with `truncate`.
    ///
    /// On error, the contents of `buf` are zeroized; its length is left unchanged.
    ///
    /// # Errors
    /// - if the `ciphertext` is inauthentic (i.e. tag verification failure)
    /// - if the `ciphertext` is too long
    /// - if the `aad` is too long
    ///
    /// # Panics
    /// If `truncate` does not truncate the buffer to the specified length in bytes.
    #[inline]
    fn decrypt_within<B: AsMut<[u8]>>(
        &self,
        nonce: &Nonce<Self>,
        aad: &[u8],
        buf: &mut B,
        truncate: impl FnOnce(&mut B, usize),
    ) -> Result<()> {
        let tag_size = Self::TagSize::USIZE;
        let buf_mut = buf.as_mut();
        let ct_len = buf_mut.len().checked_sub(tag_size).ok_or(Error)?;

        let (ct, tag) = match Self::TAG_POSITION {
            Postfix => buf_mut.split_at_mut(ct_len),
            Prefix => {
                let (tag, ct) = buf_mut.split_at_mut(tag_size);
                (ct, tag)
            }
        };

        let tag: &mut Tag<Self> = tag.try_into().expect("`tag` has correct length");
        self.decrypt_detached(nonce, aad, ct, tag)
            // On failure the `ct` part should be zeroized by the decryption function
            .inspect_err(|_| tag.fill(0))?;

        if Self::TAG_POSITION == Prefix {
            buf_mut.copy_within(tag_size.., 0);
        }

        truncate(buf, ct_len);
        assert_eq!(
            buf.as_mut().len(),
            ct_len,
            "`truncate` function did not truncate the buffer to the requested size",
        );

        Ok(())
    }
}

/// Enum which specifies tag position used by an AEAD algorithm.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TagPosition {
    /// Postfix tag
    Postfix,
    /// Prefix tag
    Prefix,
}

/// Error type.
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
