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
mod high_aead;
#[cfg(feature = "alloc")]
pub use high_aead::{Aead, Payload};

#[cfg(feature = "rand_core")]
pub use common::{Generate, rand_core};
pub use inout;

pub use common::{
    self, Key, KeyInit, KeySizeUser,
    array::{self, typenum::consts},
};
pub use inout::InOutBuf;

use common::array::{Array, ArraySize};
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
    /// The length of a nonce in bytes.
    type NonceSize: ArraySize;

    /// The length of a tag in bytes.
    type TagSize: ArraySize;

    /// Encrypt the data in the provided [`InOutBuf`], returning the authentication tag.
    ///
    /// # Errors
    /// AEAD algorithm implementations may return an error if the plaintext or AAD are too long.
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag<Self>>;

    /// Decrypt the data in the provided [`InOutBuf`], returning an error in the event the
    /// provided authentication tag is invalid for the given ciphertext (i.e. ciphertext
    /// is modified/unauthentic).
    ///
    /// # Errors
    /// - if the `ciphertext` is inauthentic (i.e. tag verification failure)
    /// - if the `ciphertext` is too long
    /// - if the `aad` is too long
    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag<Self>,
    ) -> Result<()>;

    /// Encrypt the data in the provided [`InOutBuf`] with variable size nonce,
    /// returning the authentication tag.
    ///
    /// # Warning
    /// Some algorithms support very short nonces. Users should exercise extreme caution
    /// while using this method since incorrect handling of nonces may defeat security
    /// provided by the algorithm.
    ///
    /// # Errors
    /// AEAD algorithm implementations may return an error if the plaintext or AAD are too long
    /// or an invalid nonce is used.
    fn encrypt_inout_with_var_nonce_detached(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag<Self>> {
        let nonce = nonce.try_into().map_err(|_| Error)?;
        self.encrypt_inout_detached(nonce, associated_data, buffer)
    }

    /// Decrypt the data in the provided [`InOutBuf`] with variable size nonce,
    /// returning an error in the event the provided authentication tag is invalid
    /// for the given ciphertext (i.e. ciphertext is modified/unauthentic).
    ///
    /// # Errors
    /// - if the `ciphertext` is inauthentic (i.e. tag verification failure)
    /// - if the `ciphertext` is too long
    /// - if the `aad` is too long
    fn decrypt_inout_with_var_nonce_detached(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag<Self>,
    ) -> Result<()> {
        let nonce = nonce.try_into().map_err(|_| Error)?;
        self.decrypt_inout_detached(nonce, associated_data, buffer, tag)
    }

    /// Encrypt the data in-place in the provided buffer, returning the authentication tag.
    ///
    /// # Errors
    /// AEAD algorithm implementations may return an error if the plaintext or AAD are too long.
    fn encrypt_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buf: &mut [u8],
    ) -> Result<Tag<Self>> {
        self.encrypt_inout_detached(nonce, associated_data, buf.into())
    }

    /// Decrypt the data in-place in the provided buffer, returning an error in the event the
    /// provided authentication tag is invalid for the given ciphertext (i.e. ciphertext
    /// is modified/unauthentic).
    ///
    /// # Errors
    /// - if the `ciphertext` is inauthentic (i.e. tag verification failure)
    /// - if the `ciphertext` is too long
    /// - if the `aad` is too long
    fn decrypt_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self>,
    ) -> Result<()> {
        self.decrypt_inout_detached(nonce, associated_data, buffer.into(), tag)
    }

    /// Encrypt the data in-place in the provided buffer with variable size nonce,
    /// returning the authentication tag.
    ///
    /// # Warning
    /// Some algorithms support very short nonces. Users should exercise extreme caution
    /// while using this method since incorrect handling of nonces may defeat security
    /// provided by the algorithm.
    ///
    /// # Errors
    /// AEAD algorithm implementations may return an error if the plaintext or AAD are too long
    /// or if provided nonce size is not supported.
    fn encrypt_with_var_nonce_detached(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        buf: &mut [u8],
    ) -> Result<Tag<Self>> {
        let nonce = nonce.try_into().map_err(|_| Error)?;
        self.encrypt_inout_detached(nonce, associated_data, buf.into())
    }

    /// Decrypt the data in-place in the provided buffer, returning an error in the event the
    /// provided authentication tag is invalid for the given ciphertext (i.e. ciphertext
    /// is modified/unauthentic).
    ///
    /// # Errors
    /// - if the `ciphertext` is inauthentic (i.e. tag verification failure)
    /// - if the `ciphertext` is too long
    /// - if the `aad` is too long
    fn decrypt_with_var_nonce_detached(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self>,
    ) -> Result<()> {
        let nonce = nonce.try_into().map_err(|_| Error)?;
        self.decrypt_inout_detached(nonce, associated_data, buffer.into(), tag)
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

/// Trait which carries the default tag position.
pub trait AeadTagPosition: AeadCore {
    /// The AEAD tag position.
    const TAG_POSITION: TagPosition;
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
