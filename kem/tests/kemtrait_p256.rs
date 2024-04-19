use kem::{Decapsulate, Encapsulate, KEM};
use p256::{ecdh::{EphemeralSecret, SharedSecret}, PublicKey};
use rand_core::CryptoRngCore;

struct KemNistP256;
struct DecapsulatorP256(EphemeralSecret);
struct EncapsulatorP256(PublicKey);
struct Secret(SharedSecret);

impl Decapsulate<PublicKey, Secret> for DecapsulatorP256 {
    type Error = ();

    fn decapsulate(&self, encapsulated_key: &PublicKey) -> Result<Secret, Self::Error> {
        Ok(Secret(self.0.diffie_hellman(encapsulated_key)))
    }
}

impl Encapsulate<PublicKey, Secret> for EncapsulatorP256 {
    type Error = ();

    fn encapsulate(&self, rng: &mut impl CryptoRngCore) -> Result<(PublicKey, Secret), Self::Error> {
        let sk = EphemeralSecret::random(rng);
        let pk = sk.public_key();

        Ok((pk, Secret(sk.diffie_hellman(&self.0))))
    }
}

impl KEM for KemNistP256 {
    type DecapsulatingKey = DecapsulatorP256;
    type EncapsulatingKey = EncapsulatorP256;
    type EncapsulatedKey = PublicKey;
    type SharedSecret = Secret;

    fn random_keypair(rng: &mut impl CryptoRngCore) -> (Self::DecapsulatingKey, Self::EncapsulatingKey) {
        let sk = EphemeralSecret::random(rng);
        let pk = sk.public_key();

        (DecapsulatorP256(sk), EncapsulatorP256(pk))
    }
}

// Helper trait so that shared secrets can be more easily tested for equality during testing
pub trait SecretBytes {
    fn as_slice(&self) -> &[u8];
}

impl SecretBytes for Secret {
    fn as_slice(&self) -> &[u8] {
        self.0.as_bytes().as_slice()
    }
}

fn test_kemtrait<K: KEM>()
where
    <K as KEM>::SharedSecret: SecretBytes,
{
    let mut rng = rand::thread_rng();
    let (sk, pk) = K::random_keypair(&mut rng);
    let (ek, ss1) = pk.encapsulate(&mut rng).expect("never fails");
    let ss2 = sk.decapsulate(&ek).expect("never fails");

    assert_eq!(ss1.as_slice(), ss2.as_slice());
}

#[test]
fn test_kemtrait_p256() {
    test_kemtrait::<KemNistP256>();
}
