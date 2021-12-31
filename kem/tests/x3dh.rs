use generic_array::{typenum::U32, GenericArray};
use kem::{AuthDecapsulator, EncappedKey, Encapsulator, Error};
use p256::ecdsa::Signature;
use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};
use x3dh_ke::{x3dh_a, x3dh_b, EphemeralKey, IdentityKey, Key, OneTimePreKey, SignedPreKey};

// The size of an encapped key
const P256_POINT_SIZE: usize = 231;

// Define the sender pubkey type. This is an identity key;
type X3DhSenderPublicKey = IdentityKey;
// Define the recipient privkey type. This is a bundle of 3 privkeys of different lifespans
struct X3DhPrivkeyBundle {
    ik: IdentityKey,
    spk: SignedPreKey,
    sig: Signature,
    opk: OneTimePreKey,
}
impl X3DhPrivkeyBundle {
    fn gen() -> X3DhPrivkeyBundle {
        let ik = IdentityKey::default();
        let spk = SignedPreKey::default();
        let sig = ik.sign(&spk.pk_to_bytes());
        let opk = OneTimePreKey::default();
        X3DhPrivkeyBundle { ik, spk, sig, opk }
    }
    fn as_pubkeys(&self) -> X3DhPubkeyBundle {
        X3DhPubkeyBundle {
            ik: self.ik.strip(),
            spk: self.spk.strip(),
            opk: self.opk.strip(),
            sig: self.sig,
        }
    }
}
// The pubkeys keys associated with a privkey bundle. In x3dh-ke, all the keys serve as both
// pubkeys and privkeys. This seems dangerous but hey this isn't prod.
type X3DhPubkeyBundle = X3DhPrivkeyBundle;

// The encapped key is just the byte repr of an ephemeral key. Impl the appropriate traits
#[derive(Debug)]
struct X3DhEncappedKey([u8; P256_POINT_SIZE]);
impl EncappedKey for X3DhEncappedKey {
    type NSecret = U32;
    type SenderPublicKey = X3DhSenderPublicKey;
    type RecipientPublicKey = X3DhPubkeyBundle;
}
impl AsRef<[u8]> for X3DhEncappedKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// The private key of an authenticated sender is just their identity key. Again, this is the same
// type as the pubkey.
type X3DhSenderPrivateKey = IdentityKey;
type SharedSecret = GenericArray<u8, <X3DhEncappedKey as EncappedKey>::NSecret>;

// Define an authenticated encapsulator. To authenticate, we need a full sender keypair.
impl Encapsulator<X3DhEncappedKey> for X3DhSenderPrivateKey {
    fn try_encap<R: RngCore + CryptoRng>(
        &self,
        _csprng: &mut R,
        recip_pubkey: &X3DhPubkeyBundle,
    ) -> Result<(X3DhEncappedKey, SharedSecret), Error> {
        // Make a new ephemeral key. This will be the encapped key
        let ek = EphemeralKey::default();
        // Deconstruct the recipient's pubkey bundle
        let X3DhPubkeyBundle { ik, spk, sig, opk } = recip_pubkey;

        // Do the X3DH operation to get the shared secret
        let shared_secret = x3dh_a(sig, self, spk, &ek, ik, opk)
            .map(|ss| SharedSecret::clone_from_slice(&ss))
            .map_err(|e| {
                println!("err {:?}", e);
                Error
            })?;
        // Serialize the ephemeral key
        let encapped_key = {
            let mut buf = [0u8; P256_POINT_SIZE];
            buf.copy_from_slice(&ek.to_bytes());
            X3DhEncappedKey(buf)
        };

        Ok((encapped_key, shared_secret))
    }
}

// Define an decapsulator. Since authenticated and unauthenticated encapped keys are represented by
// the same type (which, outside of testing, should not be the case), this can do both auth'd and
// unauth'd decapsulation.
impl AuthDecapsulator<X3DhEncappedKey> for X3DhPrivkeyBundle {
    fn try_auth_decap(
        &self,
        encapped_key: &X3DhEncappedKey,
        sender_pubkey: &X3DhSenderPublicKey,
    ) -> Result<SharedSecret, Error> {
        // First parse the encapped key, since it's just bytes right now
        let deserialized_ek = EphemeralKey::from_bytes(&encapped_key.0).map_err(|_| Error)?;
        // Deconstruct our private keys bundle
        let X3DhPubkeyBundle {
            ik,
            spk,
            sig: _,
            opk,
        } = self;

        // Now decapsulate
        let buf = x3dh_b(sender_pubkey, spk, &deserialized_ek, ik, opk);
        Ok(SharedSecret::clone_from_slice(&buf))
    }
}

#[test]
fn test_x3dh() {
    let mut rng = OsRng;

    // We use _a and _b suffixes to denote whether a key belongs to Alice or Bob. Alice is the
    // sender in this case.
    let sk_ident_a = X3DhSenderPrivateKey::default();
    let pk_ident_a = sk_ident_a.strip();
    let sk_bundle_b = X3DhPrivkeyBundle::gen();
    let pk_bundle_b = sk_bundle_b.as_pubkeys();

    // Now do an authenticated encap
    let (encapped_key, ss1) = sk_ident_a.try_encap(&mut rng, &pk_bundle_b).unwrap();
    let ss2 = sk_bundle_b
        .try_auth_decap(&encapped_key, &pk_ident_a)
        .unwrap();
    assert_eq!(ss1, ss2);

    // Now do an invalid authenticated encap, where the sender uses the wrong private key. This
    // should produce unequal shared secrets.
    let sk_ident_rando = X3DhSenderPrivateKey::default();
    let (encapped_key, ss1) = sk_ident_rando.try_encap(&mut rng, &pk_bundle_b).unwrap();
    let ss2 = sk_bundle_b
        .try_auth_decap(&encapped_key, &pk_ident_a)
        .unwrap();
    assert_ne!(ss1, ss2);
}
