#![doc = include_str!("../README.md")]
#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_root_url = "https://docs.rs/kem"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, unused_qualifications, missing_debug_implementations)]

use core::fmt::Debug;
use rand_core::CryptoRngCore;

/// A value that can be encapsulated to. Often, this will just be a public key. However, it can
/// also be a bundle of public keys, or it can include a sender's private key for authenticated
/// encapsulation.
pub trait Encapsulate<EK, SS> {
    /// Encapsulation error
    type Error: Debug;

    /// Encapsulates a fresh shared secret
    fn encapsulate(&self, rng: &mut impl CryptoRngCore) -> Result<(EK, SS), Self::Error>;
}

/// A value that can be used to decapsulate an encapsulated key. Often, this will just be a secret
/// key. But, as with [`Encapsulate`], it can be a bundle of secret keys, or it can include a
/// sender's private key for authenticated encapsulation.
pub trait Decapsulate<EK, SS> {
    /// Decapsulation error
    type Error: Debug;

    /// Decapsulates the given encapsulated key
    fn decapsulate(&self, encapsulated_key: &EK) -> Result<SS, Self::Error>;
}

/// This trait represents a simplified KEM model, where the encapsulating key and public key are the
/// same type.
pub trait SimpleKEM {
    /// The type that will implement [`Decapsulate`]
    type DecapsulatingKey: Decapsulate<Self::EncapsulatedKey, Self::SharedSecret>;

    /// The type that will implement [`Encapsulate`]
    type EncapsulatingKey: Encapsulate<Self::EncapsulatedKey, Self::SharedSecret>;

    /// The type of the encapsulated key
    type EncapsulatedKey;

    /// The type of the shared secret
    type SharedSecret;

    /// Generates a new (decapsulating key, encapsulating key) keypair for the KEM model
    fn random_keypair(
        rng: &mut impl CryptoRngCore,
    ) -> (Self::DecapsulatingKey, Self::EncapsulatingKey);

    /// Forwards a call to [`encapsulate`](Encapsulate::encapsulate)
    fn encapsulate(
        ek: &Self::EncapsulatingKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<
        (Self::EncapsulatedKey, Self::SharedSecret),
        <Self::EncapsulatingKey as Encapsulate<Self::EncapsulatedKey, Self::SharedSecret>>::Error,
    > {
        ek.encapsulate(rng)
    }

    /// Forwards a call to [`decapsulate`](Decapsulate::decapsulate)
    fn decapsulate(
        dk: &Self::DecapsulatingKey,
        ek: &Self::EncapsulatedKey,
    ) -> Result<
        Self::SharedSecret,
        <Self::DecapsulatingKey as Decapsulate<Self::EncapsulatedKey, Self::SharedSecret>>::Error,
    > {
        dk.decapsulate(ek)
    }
}

/// This is a trait that all KEM models should implement. It represents all the stages and types
/// necessary for a KEM.
///
/// In particular,
///
/// 1. `KeyGen() -> (PrivateKey, PublicKey)`
/// 2. `Encaps(EncapsulatingKey) -> (EncappedKey, SharedSecret)`
/// 3. `Decaps(DecapsulatingKey, EncappedKey) -> SharedSecret`
///
/// Promotion from [`PrivateKey`](FullKEM::PrivateKey) to
/// [`DecapsulatingKey`](FullKEM::DecapsulatingKey) and [`PublicKey`](FullKEM::PublicKey) to
/// [`EncapsulatingKey`](FullKEM::EncapsulatingKey) is context dependent.
pub trait FullKEM {
    /// The private key produced by [`random_keypair`](FullKEM::random_keypair)
    type PrivateKey;

    /// The public key produced by [`random_keypair`](FullKEM::random_keypair)
    type PublicKey;

    /// The type that will implement [`Decapsulate`]
    type DecapsulatingKey: Decapsulate<Self::EncapsulatedKey, Self::SharedSecret>;

    /// The type that will implement [`Encapsulate`]
    type EncapsulatingKey: Encapsulate<Self::EncapsulatedKey, Self::SharedSecret>;

    /// The type of the encapsulated key
    type EncapsulatedKey;

    /// The type of the shared secret
    type SharedSecret;

    /// Generates a new ([`PrivateKey`](FullKEM::PrivateKey), [`PublicKey`](FullKEM::PublicKey))
    /// keypair for the KEM model
    fn random_keypair(rng: &mut impl CryptoRngCore) -> (Self::PrivateKey, Self::PublicKey);

    /// Forwards a call to [`encapsulate`](Encapsulate::encapsulate)
    fn encapsulate(
        ek: &Self::EncapsulatingKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<
        (Self::EncapsulatedKey, Self::SharedSecret),
        <Self::EncapsulatingKey as Encapsulate<Self::EncapsulatedKey, Self::SharedSecret>>::Error,
    > {
        ek.encapsulate(rng)
    }

    /// Forwards a call to [`decapsulate`](Decapsulate::decapsulate)
    fn decapsulate(
        dk: &Self::DecapsulatingKey,
        ek: &Self::EncapsulatedKey,
    ) -> Result<
        Self::SharedSecret,
        <Self::DecapsulatingKey as Decapsulate<Self::EncapsulatedKey, Self::SharedSecret>>::Error,
    > {
        dk.decapsulate(ek)
    }
}

impl<K: SimpleKEM> FullKEM for K {
    type PrivateKey = K::DecapsulatingKey;
    type PublicKey = K::EncapsulatingKey;
    type DecapsulatingKey = K::DecapsulatingKey;
    type EncapsulatingKey = K::EncapsulatingKey;
    type EncapsulatedKey = K::EncapsulatedKey;
    type SharedSecret = K::SharedSecret;

    fn random_keypair(rng: &mut impl CryptoRngCore) -> (Self::PrivateKey, Self::PublicKey) {
        Self::random_keypair(rng)
    }
}
