#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, unused_qualifications, missing_debug_implementations)]

pub use common::{
    self, Generate, InvalidKey, Key, KeyExport, KeyInit, KeySizeUser, TryKeyInit, typenum::consts,
};

use common::array::{self, ArraySize};
use core::fmt::Debug;
use core::{array::TryFromSliceError, convert::Infallible};
use rand_core::CryptoRng;

#[cfg(feature = "getrandom")]
use common::getrandom::{SysRng, rand_core::UnwrapErr};

/// KEM decryption key (i.e. private key) which can decrypt encrypted shared secret ciphertexts
/// which were encrypted by [`EncapsulationKey<K>`].
pub type DecapsulationKey<K> = <K as Kem>::DecapsulationKey;

/// KEM encryption key (i.e. public key) which encrypts shared secrets into ciphertexts which
/// can be decrypted by [`DecapsulationKey<K>`].
pub type EncapsulationKey<K> = <K as Kem>::EncapsulationKey;

/// Shared key: plaintext produced after decapsulation by [`Decapsulate::decapsulate`] which is
/// also returned by [`Encapsulate::encapsulate`], which is the shared secret resulting from the
/// key encapsulation algorithm.
pub type SharedKey<K> = array::Array<u8, <K as Kem>::SharedKeySize>;

/// Ciphertext message (a.k.a. "encapsulated key") produced by [`Encapsulate::encapsulate`] which is
/// an encrypted [`SharedKey`] that can be decrypted using [`Decapsulate::decapsulate`].
pub type Ciphertext<K> = array::Array<u8, <K as Kem>::CiphertextSize>;

/// Key encapsulation mechanism.
///
/// This trait describes the entire type family used by a KEM.
pub trait Kem: Copy + Clone + Debug + Default + Eq + Ord + Send + Sync + 'static {
    /// KEM decryption key (i.e. private key) which can decrypt encrypted shared secret ciphertexts
    /// which were encrypted by [`Kem::EncapsulationKey`].
    type DecapsulationKey: TryDecapsulate<Self> + Generate;

    /// KEM encryption key (i.e. public key) which encrypts shared secrets into ciphertexts which
    /// can be decrypted by [`Kem::DecapsulationKey`].
    type EncapsulationKey: Encapsulate<Self> + Clone + Debug + Eq;

    /// Size of the shared key/secret returned by both encapsulation and decapsulation.
    type SharedKeySize: ArraySize;

    /// Size of the ciphertext (a.k.a. "encapsulated key") produced by [`Self::EncapsulationKey`].
    type CiphertextSize: ArraySize;

    /// Generate a random KEM keypair using the provided random number generator.
    fn generate_keypair_from_rng<R: CryptoRng>(
        rng: &mut R,
    ) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        let dk = Self::DecapsulationKey::generate_from_rng(rng);
        let ek = dk.as_ref().clone();
        (dk, ek)
    }

    /// Generate a random KEM keypair using the system's secure RNG.
    #[cfg(feature = "getrandom")]
    fn generate_keypair() -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        Self::generate_keypair_from_rng(&mut UnwrapErr(SysRng))
    }
}

/// Encapsulator for shared secrets.
///
/// Often, this will just be a public key. However, it can also be a bundle of public keys, or it
/// can include a sender's private key for authenticated encapsulation.
pub trait Encapsulate<K: Kem>: TryKeyInit + KeyExport {
    /// Encapsulates a fresh [`SharedKey`] generated using the supplied random number
    /// generator `R`.
    fn encapsulate_with_rng<R>(&self, rng: &mut R) -> (Ciphertext<K>, SharedKey<K>)
    where
        R: CryptoRng + ?Sized;

    /// Encapsulate a fresh shared secret generated using the system's secure RNG.
    #[cfg(feature = "getrandom")]
    fn encapsulate(&self) -> (Ciphertext<K>, SharedKey<K>) {
        self.encapsulate_with_rng(&mut UnwrapErr(SysRng))
    }
}

/// Decapsulator for encapsulated keys, with an associated `Encapsulator` bounded by the
/// [`Encapsulate`] trait.
///
/// Often, this will just be a secret key. But, as with [`Encapsulate`], it can be a bundle
/// of secret keys, or it can include a sender's private key for authenticated encapsulation.
/// It could also be a hardware device like an HSM, TPM, or SEP.
///
/// When possible (i.e. for software / non-HSM implementations) types which impl this trait should
/// also impl the [`Generate`] trait to support key generation.
pub trait Decapsulate<K: Kem>: TryDecapsulate<K, Error = Infallible> {
    /// Decapsulates the given [`Ciphertext`] a.k.a. "encapsulated key".
    fn decapsulate(&self, ct: &Ciphertext<K>) -> SharedKey<K>;

    /// Decapsulate the given byte slice containing a  [`Ciphertext`] a.k.a. "encapsulated key".
    ///
    /// # Errors
    /// - If the length of `ct` is not equal to `<Self as Kem>::CiphertextSize`.
    fn decapsulate_slice(&self, ct: &[u8]) -> Result<SharedKey<K>, TryFromSliceError> {
        ct.try_into().map(|ct| self.decapsulate(&ct))
    }
}

/// Decapsulator for encapsulated keys with failure handling, with an associated `Encapsulator`
/// bounded by the [`Encapsulate`] trait.
///
/// Prefer to implement the [`Decapsulate`] trait if possible. See that trait's documentation for
/// more information.
pub trait TryDecapsulate<K: Kem>: AsRef<K::EncapsulationKey> {
    /// Decapsulation error
    type Error: core::error::Error;

    /// Decapsulates the given [`Ciphertext`] a.k.a. "encapsulated key".
    fn try_decapsulate(&self, ct: &Ciphertext<K>) -> Result<SharedKey<K>, Self::Error>;

    /// Decapsulate the given byte slice containing a  [`Ciphertext`] a.k.a. "encapsulated key".
    ///
    /// # Errors
    /// - If the length of `ct` is not equal to `<Self as Kem>::CiphertextSize`.
    fn try_decapsulate_slice(&self, ct: &[u8]) -> Result<SharedKey<K>, Self::Error>
    where
        Self::Error: From<TryFromSliceError>,
    {
        self.try_decapsulate(ct.try_into()?)
    }
}

impl<D, K> TryDecapsulate<K> for D
where
    D: Decapsulate<K>,
    K: Kem,
{
    type Error = Infallible;

    fn try_decapsulate(&self, ct: &Ciphertext<K>) -> Result<SharedKey<K>, Infallible> {
        Ok(self.decapsulate(ct))
    }
}
