use kem::{Decapsulate, Encapsulate};

use pqcrypto::kem::firesaber::{
    decapsulate, encapsulate, keypair, Ciphertext as SaberEncappedKey, PublicKey, SecretKey,
    SharedSecret as SaberSharedSecret,
};
use rand_core::CryptoRngCore;

// We have to define a newtype for the public and private keys because we're gonna impl
// the Encapsulate and Decapsulate traits for them
struct SaberPublicKey(PublicKey);
struct SaberPrivateKey(SecretKey);

impl Encapsulate<SaberEncappedKey, SaberSharedSecret> for SaberPublicKey {
    // TODO: Encapsulation is infallible. Make this the never type once it's available
    type Error = ();

    fn encapsulate(
        &self,
        _: impl CryptoRngCore,
    ) -> Result<(SaberEncappedKey, SaberSharedSecret), ()> {
        let (ss, ek) = encapsulate(&self.0);
        Ok((ek, ss))
    }
}

impl Decapsulate<SaberEncappedKey, SaberSharedSecret> for SaberPrivateKey {
    // TODO: Decapsulation is infallible. Make this the never type once it's available
    type Error = ();

    fn decapsulate(&self, ek: &SaberEncappedKey) -> Result<SaberSharedSecret, ()> {
        Ok(decapsulate(ek, &self.0))
    }
}

fn gen_keypair() -> (SaberPublicKey, SaberPrivateKey) {
    let (pk, sk) = keypair();
    (SaberPublicKey(pk), SaberPrivateKey(sk))
}

#[test]
fn test_saber() {
    use pqcrypto_traits::kem::SharedSecret as _;
    let mut rng = rand::thread_rng();

    // Make a recipient keypair
    let (pk_recip, sk_recip) = gen_keypair();

    // Encapsulate and decapsulate. Assert that the shared secrets are equal
    let (ek, ss1) = pk_recip.encapsulate(&mut rng).unwrap();
    let ss2 = sk_recip.decapsulate(&ek).unwrap();
    assert_eq!(ss1.as_bytes(), ss2.as_bytes());
}
