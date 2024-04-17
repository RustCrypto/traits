//! # ECDH as a KEM
//!
//! This module turns the existing ECDH implementation into a suitable KEM by
//! modeling encapsulation of `g^x` as the generation of another ephemeral secret
//! `y`, computing the encapsulated ciphertext as `g^y`, and computing the shared
//! secret `g^xy`. Decapsulation of `x` is modelled as computing the shared secret
//! `g^xy` from `g^y`.
//!
//! # ECDH-KEM Usage
//!
//! ECDH-KEM allows for an unauthenticated key agreement protocol as follows
//!
//! 1. The client generates an [`EphemeralSecret`] value
//! 2. The client sends the corresponding [`PublicKey`] for their secret
//! 3. The server runs [`encapsulate`](Encapsulate::encapsulate) on the given
//!    [`PublicKey`] and holds on to the resulting [`SharedSecret`]
//! 4. The client runs [`decapsulate`](Decapsulate::decapsulate) on the
//!    "encapsulated" [`PublicKey`] returned by the server and uses the resulting
//!    [`SharedSecret`]

use crate::{CurveArithmetic, PublicKey};
use crate::ecdh::{EphemeralSecret, SharedSecret};
use kem::{Decapsulate, Encapsulate};

impl<C> Decapsulate<PublicKey<C>, SharedSecret<C>> for EphemeralSecret<C>
where
    C: CurveArithmetic,
{
    type Error = ();

    fn decapsulate(&self, encapsulated_key: &PublicKey<C>) -> Result<SharedSecret<C>, Self::Error> {
        Ok(self.diffie_hellman(encapsulated_key))
    }
}

impl<C> Encapsulate<PublicKey<C>, SharedSecret<C>> for EphemeralSecret<C>
where
    C: CurveArithmetic,
{
    type Error = ();

    fn encapsulate(&self, rng: &mut impl rand_core::CryptoRngCore) -> Result<(PublicKey<C>, SharedSecret<C>), Self::Error> {
        // generate another ephemeral ecdh secret
        let secret = EphemeralSecret::<C>::random(rng);
        let pk = secret.public_key();
        let ss = self.diffie_hellman(&pk);

        Ok((pk, ss))
    }
}
