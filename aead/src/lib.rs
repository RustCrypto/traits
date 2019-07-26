//! A set of traits designed to support authenticated encryption.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::{
    convert::TryFrom,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
};
use failure::Fail;
use generic_array::{
    typenum::{Unsigned, U0},
    ArrayLength,
};
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialze};

/// An enum describing possible failure modes
#[cfg(feature = "serde")]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Fail, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum AeadError {
    /// The nonce provided is the wrong size for this algorithm.
    #[fail(display = "The nonce given is the wrong size for the algorithm")]
    InvalidNonceSize,
    /// The ciphertext buffer is not a multiple of the block size
    #[fail(display = "The buffer given is the wrong size for the algorithm")]
    InvalidBufferSize,
    /// The "bytes used" provided is larger than the provided buffer
    #[fail(display = "The buffer usage is larger than the buffer size")]
    InvalidBufferUsed,
    /// The authentication tag is not the correct size
    #[fail(display = "The authentication tag is the wrong size for the algorithm")]
    InvalidTagSize,
    /// The cipher key was not the size of a block
    #[fail(display = "The cipher key given on creation was the wrong size")]
    InvalidCipherKeySize,
    /// The initialization vector was not the size of a block
    #[fail(display = "The IV given on creation was the wrong size")]
    InvalidIvSize,
    /// The authentication tag is not the size expected by this algorithm
    #[fail(display = "The key used for the authentication algorithm was the wrong size")]
    InvalidTagKeySize,

    #[fail(
        display = "The given ciphertext is larger than the maximum size allowed by this algorithm"
    )]
    CiphertextTooLarge,
    #[fail(
        display = "The given plaintext is larger than the maximum size allowed by this algorithm"
    )]
    PlaintextTooLarge,

    /// The MAC failed to validate. This should be used to indicated a modified
    /// ciphertext, modified additional data, or key mismatch.
    #[fail(display = "The MAC failed to validate")]
    MacFailure,
    /// There was an error parsing the padding of this message
    #[fail(display = "The padding was not correct")]
    PaddingFailure,
}

/// An enum describing possible failure modes
#[cfg(not(feature = "serde"))]
#[derive(Clone, Copy, Debug, Eq, Fail, Hash, Ord, PartialEq, PartialOrd)]
pub enum AeadError {
    /// The nonce provided is the wrong size for this algorithm.
    #[fail(display = "The nonce given is the wrong size for the algorithm")]
    InvalidNonceSize,
    /// The ciphertext buffer is not a multiple of the block size
    #[fail(display = "The buffer given is the wrong size for the algorithm")]
    InvalidBufferSize,
    /// The "bytes used" provided is larger than the provided buffer
    #[fail(display = "The buffer usage is larger than the buffer size")]
    InvalidBufferUsed,
    /// The authentication tag is not the correct size
    #[fail(display = "The authentication tag is the wrong size for the algorithm")]
    InvalidTagSize,
    /// The cipher key was not the size of a block
    #[fail(display = "The cipher key given on creation was the wrong size")]
    InvalidCipherKeySize,
    /// The initialization vector was not the size of a block
    #[fail(display = "The IV given on creation was the wrong size")]
    InvalidIvSize,
    /// The authentication tag is not the size expected by this algorithm
    #[fail(display = "The key used for the authentication algorithm was the wrong size")]
    InvalidTagKeySize,

    #[fail(
        display = "The given ciphertext is larger than the maximum size allowed by this algorithm"
    )]
    CiphertextTooLarge,
    #[fail(
        display = "The given plaintext is larger than the maximum size allowed by this algorithm"
    )]
    PlaintextTooLarge,

    /// The MAC failed to validate. This should be used to indicated a modified
    /// ciphertext, modified additional data, or key mismatch.
    #[fail(display = "The MAC failed to validate")]
    MacFailure,
    /// There was an error parsing the padding of this message
    #[fail(display = "The padding was not correct")]
    PaddingFailure,
}

/// A trait used to tag ciphertext inputs/outputs for an authenticated block cipher
pub trait Ciphertext:
    Clone
    + Debug
    + Display
    + Into<Vec<u8>>
    + Send
    + Sized
    + Sync
    + for<'bytes> TryFrom<&'bytes [u8], Error = AeadError>
{
    /// Retrieve the length of the ciphertext, in bytes
    fn len(&self) -> usize;
}

/// An explicit cryptographic nonce, which may be optionally used for
/// authenticated block ciphers.
pub trait Nonce:
    Clone
    + Debug
    + Display
    + Into<Vec<u8>>
    + Send
    + Sized
    + Sync
    + for<'bytes> TryFrom<&'bytes [u8], Error = AeadError>
{
    /// The length of an explicit nonce, in bytes.
    type Len: ArrayLength<u8> + Unsigned;
}

/// A standard nonce implementation for AEAD algorithms which do not use
/// explicit nonces.
#[cfg(feature = "serde")]
#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct EmptyNonce;
#[cfg(not(feature = "serde"))]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EmptyNonce;

/// Output an empty-array style string for the EmptyNonce display.
impl Display for EmptyNonce {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "[]")
    }
}

/// Size restrictions for the Emtpy Nonce type
impl Nonce for EmptyNonce {
    type Len = U0;
}

/// An empty nonce can be converted into an empty vector
impl Into<Vec<u8>> for EmptyNonce {
    fn into(self) -> Vec<u8> {
        Vec::default()
    }
}

/// Load this nonce from a byte slice (myst be zero-length)
impl<'bytes> TryFrom<&'bytes [u8]> for EmptyNonce {
    type Error = AeadError;

    fn try_from(src: &[u8]) -> Result<Self, Self::Error> {
        if src.len() != 0 {
            Err(AeadError::InvalidNonceSize)
        } else {
            Ok(EmptyNonce)
        }
    }
}

/// A trait which can support an RFC5116-style authenticated encryption scheme.
///
/// In order to reduce the opportunity for misuse, the nonce used for
/// encryption is meant to be managed internally by the implementation itself.
pub trait AuthenticatedBlockCipher: Sized + Send + Sync
where
    for<'ciphertext> Vec<u8>: From<&'ciphertext Self::Ciphertext>,
{
    /// The message encapsulation type
    type Ciphertext: Ciphertext;

    /// The cryptographic nonce object used for this cipher
    type Nonce: Nonce;

    /// Encrypts the given plaintext into a new ciphertext object and the nonce
    fn encrypt<'ad, RngType: CryptoRng + RngCore>(
        &mut self,
        csprng: &mut RngType,
        additional_data: impl Iterator<Item = &'ad [u8]>,
        plaintext: &[u8],
    ) -> Result<(Self::Ciphertext, Self::Nonce), AeadError>;

    /// Authenticates the ciphertext, nonce, and additional data, then
    /// decrypts the ciphertext contents into plaintext.   
    fn decrypt<'ad>(
        &self,
        additional_data: impl Iterator<Item = &'ad [u8]>,
        nonce: Self::Nonce,
        ciphertext: Self::Ciphertext,
    ) -> Result<Vec<u8>, AeadError>;
}
