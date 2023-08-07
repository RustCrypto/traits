use hpke::{
    kem::{Kem as KemTrait, X25519HkdfSha256},
    Deserializable as HpkeDeserializable, Serializable as HpkeSerializable,
};
use kem::{
    generic_array::GenericArray, AuthDecapsulator, Decapsulator, EncappedKey, Encapsulator, Error,
    SharedSecret,
};
use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};

// Define the pubkey type. This has no trait bounds required by the library
#[derive(Clone)]
struct X25519PublicKey(<X25519HkdfSha256 as KemTrait>::PublicKey);

// Define the encapsulated key type and impl the necessary traits. Since authenticated and
// unauthenticated DHKEMs have the same encapped key type, this will support both types of
// algorithms. In practice, one should use types to distinguish between the two. But this is just
// test code, so whatever.
#[derive(Debug)]
struct X25519EncappedKey(
    // It's just an array of bytes
    GenericArray<u8, <<X25519HkdfSha256 as KemTrait>::EncappedKey as HpkeSerializable>::OutputSize>,
);
impl EncappedKey for X25519EncappedKey {
    type SharedSecretSize = <X25519HkdfSha256 as KemTrait>::NSecret;
    type EncappedKeySize =
        <<X25519HkdfSha256 as KemTrait>::PublicKey as HpkeSerializable>::OutputSize;
    // In HPKE the only recipient public key is the identity key
    type RecipientPublicKey = X25519PublicKey;
    // The sender's pubkey is the identity too
    type SenderPublicKey = X25519PublicKey;

    fn from_bytes(bytes: &GenericArray<u8, Self::EncappedKeySize>) -> Result<Self, Error> {
        Ok(X25519EncappedKey(*bytes))
    }
}
impl AsRef<[u8]> for X25519EncappedKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// Define some convenience types
type X25519PrivateKey = <X25519HkdfSha256 as KemTrait>::PrivateKey;
type X25519SharedSecret = SharedSecret<X25519EncappedKey>;

// Define an authenticated encapsulator. To authenticate, we need a full sender keypair.
struct X25519AuthEncap(X25519PrivateKey, X25519PublicKey);
impl Encapsulator<X25519EncappedKey> for X25519AuthEncap {
    fn try_encap<R: RngCore + CryptoRng>(
        &self,
        csprng: &mut R,
        recip_pubkey: &X25519PublicKey,
    ) -> Result<(X25519EncappedKey, X25519SharedSecret), Error> {
        <X25519HkdfSha256 as KemTrait>::encap(&recip_pubkey.0, Some((&self.0, &(self.1).0)), csprng)
            .map(|(ss, ek)| {
                (
                    X25519EncappedKey(ek.to_bytes()),
                    X25519SharedSecret::new(ss.0),
                )
            })
            .map_err(|_| Error)
    }
}

// Define an unauthenticated encapsulator. This doesn't need any state at all.
struct X25519Encap;
impl Encapsulator<X25519EncappedKey> for X25519Encap {
    fn try_encap<R: RngCore + CryptoRng>(
        &self,
        csprng: &mut R,
        recip_pubkey: &X25519PublicKey,
    ) -> Result<(X25519EncappedKey, X25519SharedSecret), Error> {
        <X25519HkdfSha256 as KemTrait>::encap(&recip_pubkey.0, None, csprng)
            .map(|(ss, ek)| {
                (
                    X25519EncappedKey(ek.to_bytes()),
                    X25519SharedSecret::new(ss.0),
                )
            })
            .map_err(|_| Error)
    }
}

// Define an decapsulator. Since authenticated and unauthenticated encapped keys are represented by
// the same type (which, outside of testing, should not be the case), this can do both auth'd and
// unauth'd decapsulation.
impl Decapsulator<X25519EncappedKey> for X25519PrivateKey {
    fn try_decap(&self, encapped_key: &X25519EncappedKey) -> Result<X25519SharedSecret, Error> {
        // First parse the encapped key, since it's just bytes right now
        let deserialized_encapped_key =
            <<X25519HkdfSha256 as KemTrait>::EncappedKey as HpkeDeserializable>::from_bytes(
                &encapped_key.0,
            )
            .map_err(|_| Error)?;

        // Now decapsulate
        <X25519HkdfSha256 as KemTrait>::decap(self, None, &deserialized_encapped_key)
            .map(|ss| SharedSecret::new(ss.0))
            .map_err(|_| Error)
    }
}
impl AuthDecapsulator<X25519EncappedKey> for X25519PrivateKey {
    fn try_auth_decap(
        &self,
        encapped_key: &X25519EncappedKey,
        sender_pubkey: &X25519PublicKey,
    ) -> Result<X25519SharedSecret, Error> {
        // First parse the encapped key, since it's just bytes right now
        let deserialized_encapped_key =
            <<X25519HkdfSha256 as KemTrait>::EncappedKey as HpkeDeserializable>::from_bytes(
                &encapped_key.0,
            )
            .map_err(|_| Error)?;

        // Now decapsulate
        <X25519HkdfSha256 as KemTrait>::decap(
            self,
            Some(&sender_pubkey.0),
            &deserialized_encapped_key,
        )
        .map(|ss| X25519SharedSecret::new(ss.0))
        .map_err(|_| Error)
    }
}

// A simple wrapper around the keypair generation function
fn gen_keypair<R: RngCore + CryptoRng>(csprng: &mut R) -> (X25519PrivateKey, X25519PublicKey) {
    let (sk, pk) = X25519HkdfSha256::gen_keypair(csprng);
    let wrapped_pk = X25519PublicKey(pk);

    (sk, wrapped_pk)
}

#[test]
fn test_hpke() {
    let mut rng = OsRng;

    // Make a sender and recipient keypair
    let (sk_sender, pk_sender) = gen_keypair(&mut rng);
    let (sk_recip, pk_recip) = gen_keypair(&mut rng);

    // Try an unauthed encap first. Check that the derived shared secrets are equal
    let encapper = X25519Encap;
    let (ek, ss1) = encapper.try_encap(&mut rng, &pk_recip).unwrap();
    let ss2 = sk_recip.try_decap(&ek).unwrap();
    assert_eq!(ss1.as_bytes(), ss2.as_bytes());

    // Now do an authenticated encap
    let encapper = X25519AuthEncap(sk_sender, pk_sender.clone());
    let (ek, ss1) = encapper.try_encap(&mut rng, &pk_recip).unwrap();
    let ss2 = sk_recip.try_auth_decap(&ek, &pk_sender).unwrap();
    assert_eq!(ss1.as_bytes(), ss2.as_bytes());

    // Now do an invalid authenticated encap, where the sender uses the wrong private key. This
    // should produce unequal shared secrets.
    let (rand_sk, _) = gen_keypair(&mut rng);
    let encapper = X25519AuthEncap(rand_sk, pk_sender.clone());
    let (ek, ss1) = encapper.try_encap(&mut rng, &pk_recip).unwrap();
    let ss2 = sk_recip.try_auth_decap(&ek, &pk_sender).unwrap();
    assert_ne!(ss1.as_bytes(), ss2.as_bytes());
}
