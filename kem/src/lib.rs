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
use core::{array::TryFromSliceError, convert::Infallible};
use rand_core::TryCryptoRng;

#[cfg(feature = "getrandom")]
use {common::getrandom, rand_core::TryRngCore};

/// Ciphertext message (a.k.a. "encapsulated key") produced by [`Encapsulate::encapsulate`] which is
/// an encrypted [`SharedSecret`] that can be decrypted using [`Decapsulate::decapsulate`].
///
/// `K` is expected to be a type that impls [`Kem`], such as an encapsulator or decapsulator.
pub type Ciphertext<K> = array::Array<u8, <K as Kem>::CiphertextSize>;

/// Shared secret: plaintext produced after decapsulation by [`Decapsulate::decapsulate`] which is
/// also returned by [`Encapsulate::encapsulate`].
///
/// `K` is expected to be a type that impls [`Kem`], such as an encapsulator or decapsulator.
pub type SharedSecret<K> = array::Array<u8, <K as Kem>::SharedSecretSize>;

/// Key encapsulation mechanism.
///
/// This trait is impl'd by types that impl either [`Encapsulate`] or [`Decapsulate`] and defines
/// the sizes of the encapsulated key and shared secret.
pub trait Kem {
    /// Size of the ciphertext (a.k.a. "encapsulated key") produced by [`Encapsulate::encapsulate`].
    type CiphertextSize: ArraySize;

    /// Size of the shared secret after decapsulation by [`Decapsulate::decapsulate`].
    type SharedSecretSize: ArraySize;
}

/// Encapsulator for shared secrets.
///
/// Often, this will just be a public key. However, it can also be a bundle of public keys, or it
/// can include a sender's private key for authenticated encapsulation.
pub trait Encapsulate: Kem + TryKeyInit + KeyExport {
    /// Encapsulates a fresh [`SharedSecret`] generated using the supplied random number
    /// generator `R`.
    fn encapsulate_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Result<(Ciphertext<Self>, SharedSecret<Self>), R::Error>;

    /// Encapsulate a fresh shared secret generated using the system's secure RNG.
    #[cfg(feature = "getrandom")]
    fn encapsulate(&self) -> (Ciphertext<Self>, SharedSecret<Self>) {
        match self.encapsulate_with_rng(&mut getrandom::SysRng.unwrap_err()) {
            Ok(ret) => ret,
        }
    }
}

/// Trait for decapsulators, which is a supertrait bound of both [`Decapsulate`] and
/// [`TryDecapsulate`].
pub trait Decapsulator:
    Kem<
        CiphertextSize = <Self::Encapsulator as Kem>::CiphertextSize,
        SharedSecretSize = <Self::Encapsulator as Kem>::SharedSecretSize,
    >
{
    /// Encapsulator which corresponds to this decapsulator.
    type Encapsulator: Encapsulate + Clone + Kem;

    /// Retrieve the encapsulator associated with this decapsulator.
    fn encapsulator(&self) -> &Self::Encapsulator;
}

impl<K: Decapsulator> Kem for K {
    type CiphertextSize = <K::Encapsulator as Kem>::CiphertextSize;
    type SharedSecretSize = <K::Encapsulator as Kem>::SharedSecretSize;
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
pub trait Decapsulate: Decapsulator + TryDecapsulate<Error = Infallible> {
    /// Decapsulates the given [`Ciphertext`] a.k.a. "encapsulated key".
    fn decapsulate(&self, ct: &Ciphertext<Self>) -> SharedSecret<Self>;

    /// Decapsulate the given byte slice containing a  [`Ciphertext`] a.k.a. "encapsulated key".
    ///
    /// # Errors
    /// - If the length of `ct` is not equal to `<Self as Kem>::CiphertextSize`.
    fn decapsulate_slice(&self, ct: &[u8]) -> Result<SharedSecret<Self>, TryFromSliceError> {
        ct.try_into().map(|ct| self.decapsulate(&ct))
    }
}

/// Decapsulator for encapsulated keys with failure handling, with an associated `Encapsulator`
/// bounded by the [`Encapsulate`] trait.
///
/// Prefer to implement the [`Decapsulate`] trait if possible. See that trait's documentation for
/// more information.
pub trait TryDecapsulate: Decapsulator {
    /// Decapsulation error
    type Error: core::error::Error;

    /// Decapsulates the given [`Ciphertext`] a.k.a. "encapsulated key".
    fn try_decapsulate(&self, ct: &Ciphertext<Self>) -> Result<SharedSecret<Self>, Self::Error>;

    /// Decapsulate the given byte slice containing a  [`Ciphertext`] a.k.a. "encapsulated key".
    ///
    /// # Errors
    /// - If the length of `ct` is not equal to `<Self as Kem>::CiphertextSize`.
    fn try_decapsulate_slice(&self, ct: &[u8]) -> Result<SharedSecret<Self>, Self::Error>
    where
        Self::Error: From<TryFromSliceError>,
    {
        self.try_decapsulate(ct.try_into()?)
    }
}

impl<D> TryDecapsulate for D
where
    D: Decapsulate,
{
    type Error = Infallible;

    fn try_decapsulate(&self, ct: &Ciphertext<Self>) -> Result<SharedSecret<Self>, Infallible> {
        Ok(self.decapsulate(ct))
    }
}
