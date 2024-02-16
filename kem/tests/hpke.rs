use kem::{Decapsulate, Encapsulate};

use hpke::{
    kem::{Kem as KemTrait, X25519HkdfSha256},
    HpkeError,
};
use rand_core::{CryptoRng, CryptoRngCore, RngCore};

type SharedSecret = hpke::kem::SharedSecret<X25519HkdfSha256>;
type EncappedKey = <X25519HkdfSha256 as KemTrait>::EncappedKey;

// We have to define a newtype for the public and private keys because we're gonna impl
// the Encapsulate and Decapsulate traits for them
struct PublicKey(<X25519HkdfSha256 as KemTrait>::PublicKey);
struct PrivateKey(<X25519HkdfSha256 as KemTrait>::PrivateKey);

impl Encapsulate<EncappedKey, SharedSecret> for PublicKey {
    type Error = HpkeError;

    fn encapsulate(
        &self,
        mut csprng: impl CryptoRngCore,
    ) -> Result<(EncappedKey, SharedSecret), HpkeError> {
        <X25519HkdfSha256 as KemTrait>::encap(&self.0, None, &mut csprng).map(|(ek, ss)| (ss, ek))
    }
}

impl Decapsulate<EncappedKey, SharedSecret> for PrivateKey {
    type Error = HpkeError;

    fn decapsulate(&self, encapped_key: &EncappedKey) -> Result<SharedSecret, HpkeError> {
        <X25519HkdfSha256 as KemTrait>::decap(&self.0, None, &encapped_key)
    }
}

// A simple wrapper around the keypair generation function
fn gen_keypair<R: RngCore + CryptoRng>(csprng: &mut R) -> (PrivateKey, PublicKey) {
    let (sk, pk) = X25519HkdfSha256::gen_keypair(csprng);
    (PrivateKey(sk), PublicKey(pk))
}

#[test]
fn test_hpke() {
    let mut rng = rand::thread_rng();

    // Make a recipient's keypair
    let (sk_recip, pk_recip) = gen_keypair(&mut rng);

    // Encapsulate to the recipient. Check that the derived shared secrets are equal
    let (ek, ss1) = pk_recip.encapsulate(&mut rng).unwrap();
    let ss2 = sk_recip.decapsulate(&ek).unwrap();
    assert_eq!(ss1.0, ss2.0);
}
