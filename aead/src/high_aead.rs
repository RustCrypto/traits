use crate::{AeadCore, AeadWithTag, Result};
use alloc::vec::Vec;

/// High-level functionality of Authenticated Encryption with Associated Data (AEAD) algorithms.
pub trait Aead {
    /// Encrypt the given plaintext payload, and return the resulting
    /// ciphertext as a vector of bytes.
    ///
    /// The [`Payload`] type can be used to provide Additional Associated Data
    /// (AAD) along with the message and nonce: this is an optional bytestring which is
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
    fn encrypt(&self, payload: Payload<'_>) -> Result<Vec<u8>>;

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
    fn decrypt(&self, payload: Payload<'_>) -> Result<Vec<u8>>;
}

impl<T: AeadCore + AeadWithTag> Aead for T {
    #[allow(clippy::unwrap_in_result)]
    fn encrypt(&self, payload: Payload<'_>) -> Result<Vec<u8>> {
        let Payload { nonce, msg, aad } = payload;
        self.encrypt_into_with_var_nonce(nonce, aad, msg, |n| alloc::vec![0u8; n])
    }

    #[allow(clippy::unwrap_in_result)]
    fn decrypt(&self, payload: Payload<'_>) -> Result<Vec<u8>> {
        let Payload { nonce, msg, aad } = payload;
        self.decrypt_into_with_var_nonce(nonce, aad, msg, |n| alloc::vec![0u8; n])
    }
}

/// AEAD payloads (nonce + message + AAD).
///
/// Combination of a nonce, a message (plaintext or ciphertext) and
/// "additional associated data" (AAD) to be authenticated (in cleartext)
/// along with the message.
///
/// If you don't care about AAD, you can pass an empty slice.
///
/// This type is used to emulate named function arguments to guard against potential bugs
/// caused by the use of the same type (`&[u8]`) by all payload parts.
#[derive(Debug)]
pub struct Payload<'a> {
    /// Nonce used for encryption/decryption.
    ///
    /// See [`Nonce`][crate::Nonce] for additional information.
    pub nonce: &'a [u8],

    /// Message to be encrypted/decrypted
    pub msg: &'a [u8],

    /// Optional "additional associated data" to authenticate along with
    /// this message. If AAD is provided at the time the message is encrypted,
    /// the same AAD *MUST* be provided at the time the message is decrypted,
    /// or decryption will fail.
    pub aad: &'a [u8],
}
