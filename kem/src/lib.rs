#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, unused_qualifications, missing_debug_implementations)]

pub use crypto_common::{Generate, KeyExport, KeySizeUser, TryKeyInit, typenum::consts};

use rand_core::TryCryptoRng;

#[cfg(feature = "getrandom")]
use {crypto_common::getrandom::SysRng, rand_core::TryRngCore};

/// Encapsulator for shared secrets.
///
/// Often, this will just be a public key. However, it can also be a bundle of public keys, or it
/// can include a sender's private key for authenticated encapsulation.
pub trait Encapsulate<EK, SS>: TryKeyInit + KeyExport {
    /// Encapsulates a fresh shared secret
    fn encapsulate_with_rng<R>(&self, rng: &mut R) -> Result<(EK, SS), R::Error>
    where
        R: TryCryptoRng + ?Sized;

    /// Encapsulate a fresh shared secret generated using the system's secure RNG.
    #[cfg(feature = "getrandom")]
    fn encapsulate(&self) -> (EK, SS) {
        let Ok(ret) = self.encapsulate_with_rng(&mut SysRng.unwrap_err());
        ret
    }
}

/// Decapsulator for an encapsulated keys, with an associated encapsulator.
///
/// Often, this will just be a secret key. But, as with [`Encapsulate`], it can be a bundle
/// of secret keys, or it can include a sender's private key for authenticated encapsulation.
///
/// When possible (i.e. for software / non-HSM implementations) types which impl this trait should
/// also impl the [`Generate`] trait to support key generation.
pub trait Decapsulate<EK, SS> {
    /// Encapsulator which corresponds to this decapsulator.
    type Encapsulator: Encapsulate<EK, SS>;

    /// Decapsulates the given encapsulated key
    fn decapsulate(&self, encapsulated_key: &EK) -> SS;

    /// Retrieve the encapsulator associated with this decapsulator.
    fn encapsulator(&self) -> Self::Encapsulator;
}
