use kem::{Decapsulate, Encapsulate};

use hpke::{
    kem::{Kem as KemTrait, X25519HkdfSha256},
    HpkeError,
};
use rand::rngs::OsRng;
use rand_core::{CryptoRng, CryptoRngCore, RngCore};

type SharedSecret = hpke::kem::SharedSecret<X25519HkdfSha256>;

// Define the pubkey type. This has no trait bounds required by the library
#[derive(Clone)]
struct X25519PublicKey(<X25519HkdfSha256 as KemTrait>::PublicKey);

struct X25519PrivateKey(<X25519HkdfSha256 as KemTrait>::PrivateKey);

type X25519EncappedKey = <X25519HkdfSha256 as KemTrait>::EncappedKey;

impl Encapsulate<X25519EncappedKey, SharedSecret> for X25519PublicKey {
    type Error = HpkeError;

    fn encapsulate(
        &self,
        mut csprng: impl CryptoRngCore,
    ) -> Result<(X25519EncappedKey, SharedSecret), HpkeError> {
        <X25519HkdfSha256 as KemTrait>::encap(&self.0, None, &mut csprng).map(|(ek, ss)| (ss, ek))
    }
}

impl Decapsulate<X25519EncappedKey, SharedSecret> for X25519PrivateKey {
    type Error = HpkeError;

    fn decapsulate(&self, encapped_key: &X25519EncappedKey) -> Result<SharedSecret, HpkeError> {
        <X25519HkdfSha256 as KemTrait>::decap(&self.0, None, &encapped_key)
    }
}

// A simple wrapper around the keypair generation function
fn gen_keypair<R: RngCore + CryptoRng>(csprng: &mut R) -> (X25519PrivateKey, X25519PublicKey) {
    let (sk, pk) = X25519HkdfSha256::gen_keypair(csprng);
    (X25519PrivateKey(sk), X25519PublicKey(pk))
}

#[test]
fn test_hpke() {
    let mut rng = OsRng;

    // Make a recipient's keypair
    let (sk_recip, pk_recip) = gen_keypair(&mut rng);

    // Encapsulate to the recipient. Check that the derived shared secrets are equal
    let (ek, ss1) = pk_recip.encapsulate(&mut rng).unwrap();
    let ss2 = sk_recip.decapsulate(&ek).unwrap();
    assert_eq!(ss1.0, ss2.0);
}
