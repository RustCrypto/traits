//! Authenticated Encryption with Associated Data (AEAD) traits
//!
//! This crate provides an abstract interface for AEAD ciphers, which guarantee
//! both confidentiality and integrity, even from a powerful attacker who is
//! able to execute [chosen-ciphertext attacks]. The resulting security property,
//! [ciphertext indistinguishability], is considered a basic requirement for
//! modern cryptographic implementations.
//!
//! See [RustCrypto/AEADs] for cipher implementations which use this trait.
//!
//! [chosen-ciphertext attacks]: https://en.wikipedia.org/wiki/Chosen-ciphertext_attack
//! [ciphertext indistinguishability]: https://en.wikipedia.org/wiki/Ciphertext_indistinguishability
//! [RustCrypto/AEADs]: https://github.com/RustCrypto/AEADs

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

pub use generic_array;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};

// Define the default implementation for both `Aead::encrypt()` and
// `AeadMut::encrypt()`. Uses a macro to gloss over `&self` vs `&mut self`.
#[cfg(feature = "alloc")]
macro_rules! encrypt_to_postfix_tagged_vec {
    ($aead:expr, $nonce:expr, $payload:expr) => {{
        let payload = $payload.into();
        let mut buffer = Vec::with_capacity(payload.msg.len() + Self::TagSize::to_usize());
        buffer.extend_from_slice(payload.msg);

        let tag = $aead.encrypt_in_place_detached($nonce, payload.aad, &mut buffer)?;
        buffer.extend_from_slice(tag.as_slice());
        Ok(buffer)
    }};
}

// Define the default implementation for both `Aead::decrypt()` and
// `AeadMut::decrypt()`. Uses a macro to gloss over `&self` vs `&mut self`.
#[cfg(feature = "alloc")]
macro_rules! decrypt_postfix_tagged_ciphertext_to_vec {
    ($aead:expr, $nonce:expr, $payload:expr) => {{
        let payload = $payload.into();

        if payload.msg.len() < Self::TagSize::to_usize() {
            return Err(Error);
        }

        let tag_start = payload.msg.len() - Self::TagSize::to_usize();
        let mut buffer = Vec::from(&payload.msg[..tag_start]);
        let tag = GenericArray::from_slice(&payload.msg[tag_start..]);
        $aead.decrypt_in_place_detached($nonce, payload.aad, &mut buffer, tag)?;

        Ok(buffer)
    }};
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Error;

/// Instantiate either a stateless [`Aead`] or stateful [`AeadMut`] algorithm.
pub trait NewAead {
    /// The size of the key array required by this algorithm.
    type KeySize: ArrayLength<u8>;

    /// Construct a new stateful instance for the given key.
    fn new(key: GenericArray<u8, Self::KeySize>) -> Self;
}

/// Authenticated Encryption with Associated Data (AEAD) algorithm.
///
/// This trait is intended for use with stateless AEAD algorithms. The
/// [`AeadMut`] trait provides a stateful interface.
pub trait Aead {
    /// The length of a nonce.
    type NonceSize: ArrayLength<u8>;
    /// The maximum length of the nonce.
    type TagSize: ArrayLength<u8>;
    /// The upper bound amount of additional space required to support a
    /// ciphertext vs. a plaintext.
    type CiphertextOverhead: ArrayLength<u8> + Unsigned;

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
    fn encrypt<'msg, 'aad>(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error> {
        encrypt_to_postfix_tagged_vec!(self, nonce, plaintext)
    }

    /// Encrypt the data in-place, returning the authentication tag
    fn encrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<GenericArray<u8, Self::TagSize>, Error>;

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
    #[cfg(feature = "alloc")]
    fn decrypt<'msg, 'aad>(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error> {
        decrypt_postfix_tagged_ciphertext_to_vec!(self, nonce, ciphertext)
    }

    /// Decrypt the data in-place, returning an error in the event the provided
    /// authentication tag does not match the given ciphertext (i.e. ciphertext
    /// is modified/unauthentic)
    fn decrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &GenericArray<u8, Self::TagSize>,
    ) -> Result<(), Error>;
}

/// Stateful Authenticated Encryption with Associated Data algorithm.
pub trait AeadMut {
    /// The length of a nonce.
    type NonceSize: ArrayLength<u8>;
    /// The maximum length of the nonce.
    type TagSize: ArrayLength<u8>;
    /// The upper bound amount of additional space required to support a
    /// ciphertext vs. a plaintext.
    type CiphertextOverhead: ArrayLength<u8> + Unsigned;

    /// Encrypt the given plaintext slice, and return the resulting ciphertext
    /// as a vector of bytes.
    ///
    /// See notes on [`Aead::encrypt()`] about allowable message payloads and
    /// Associated Additional Data (AAD).
    #[cfg(feature = "alloc")]
    fn encrypt<'msg, 'aad>(
        &mut self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error> {
        encrypt_to_postfix_tagged_vec!(self, nonce, plaintext)
    }

    /// Encrypt the data in-place, returning the authentication tag
    fn encrypt_in_place_detached(
        &mut self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<GenericArray<u8, Self::TagSize>, Error>;

    /// Decrypt the given ciphertext slice, and return the resulting plaintext
    /// as a vector of bytes.
    ///
    /// See notes on [`Aead::encrypt()`] and [`Aead::decrypt()`] about allowable
    /// message payloads and Associated Additional Data (AAD).
    #[cfg(feature = "alloc")]
    fn decrypt<'msg, 'aad>(
        &mut self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error> {
        decrypt_postfix_tagged_ciphertext_to_vec!(self, nonce, ciphertext)
    }

    /// Decrypt the data in-place, returning an error in the event the provided
    /// authentication tag does not match the given ciphertext (i.e. ciphertext
    /// is modified/unauthentic)
    fn decrypt_in_place_detached(
        &mut self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &GenericArray<u8, Self::TagSize>,
    ) -> Result<(), Error>;
}

/// A blanket implementation of the Stateful AEAD interface for Stateless
/// AEAD implementations.
impl<Algo: Aead> AeadMut for Algo {
    type NonceSize = Algo::NonceSize;
    type TagSize = Algo::TagSize;
    type CiphertextOverhead = Algo::CiphertextOverhead;

    /// Encrypt the given plaintext slice, and return the resulting ciphertext
    /// as a vector of bytes.
    #[cfg(feature = "alloc")]
    fn encrypt<'msg, 'aad>(
        &mut self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error> {
        <Self as Aead>::encrypt(self, nonce, plaintext)
    }

    /// Encrypt the data in-place, returning the authentication tag
    fn encrypt_in_place_detached(
        &mut self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<GenericArray<u8, Self::TagSize>, Error> {
        <Self as Aead>::encrypt_in_place_detached(self, nonce, associated_data, buffer)
    }

    /// Decrypt the given ciphertext slice, and return the resulting plaintext
    /// as a vector of bytes.
    #[cfg(feature = "alloc")]
    fn decrypt<'msg, 'aad>(
        &mut self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error> {
        <Self as Aead>::decrypt(self, nonce, ciphertext)
    }

    /// Decrypt the data in-place, returning an error in the event the provided
    /// authentication tag does not match the given ciphertext (i.e. ciphertext
    /// is modified/unauthentic)
    fn decrypt_in_place_detached(
        &mut self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &GenericArray<u8, Self::TagSize>,
    ) -> Result<(), Error> {
        <Self as Aead>::decrypt_in_place_detached(self, nonce, associated_data, buffer, tag)
    }
}

/// AEAD payloads are a combination of a message (plaintext or ciphertext)
/// and "additional associated data" (AAD) to be authenticated (in cleartext)
/// along with the message.
///
/// If you don't care about AAD, you can pass a `&[u8]` as the payload to
/// `encrypt`/`decrypt` and it will automatically be coerced to this type.
pub struct Payload<'msg, 'aad> {
    /// Message to be encrypted/decrypted
    pub msg: &'msg [u8],

    /// Optional "additional associated data" to authenticate along with
    /// this message. If AAD is provided at the time the message is encrypted,
    /// the same AAD *MUST* be provided at the time the message is decrypted,
    /// or decryption will fail.
    pub aad: &'aad [u8],
}

impl<'msg, 'aad> From<&'msg [u8]> for Payload<'msg, 'aad> {
    fn from(msg: &'msg [u8]) -> Self {
        Self { msg, aad: b"" }
    }
}
