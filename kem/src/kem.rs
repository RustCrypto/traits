//! KEM Traits

use rand_core::CryptoRngCore;

/// A value that can be encapsulated to. Often, this will just be a public key. However,
/// it can also be a bundle of public keys, or it can include a sender's private key for
/// authenticated encapsulation.
pub trait Encapsulate<EK, SS> {
    /// Encapsulation error
    type Error;

    /// Encapsulates a fresh shared secret
    fn encapsulate(&self, rng: impl CryptoRngCore) -> Result<(EK, SS), Self::Error>;
}

/// A value that can be used to decapsulate an encapsulated key. Often, this will just
/// be a secret key. But, as with [`Encapsulate`], it can be a bundle of secret keys,
/// or it can include a sender's private key for authenticated encapsulation.
pub trait Decapsulate<EK, SS> {
    /// Decapsulation error
    type Error;

    /// Decapsulates the given encapsulated key
    fn decapsulate(&self, encapsulated_key: &EK) -> Result<SS, Self::Error>;
}
