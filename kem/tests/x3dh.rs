use kem::{Decapsulate, Encapsulate};

use p256::ecdsa::Signature;
use rand_core::CryptoRngCore;
use x3dh_ke::{x3dh_a, x3dh_b, EphemeralKey, IdentityKey, Key, OneTimePreKey, SignedPreKey};

/// The shared secret type defined by x3dh_ke
type SharedSecret = [u8; 32];

// Define the recipient privkey type. This is a bundle of 3 privkeys of different lifespans
struct X3DhPrivkeyBundle {
    ik: IdentityKey,
    spk: SignedPreKey,
    sig: Signature,
    opk: OneTimePreKey,
}

impl X3DhPrivkeyBundle {
    fn gen() -> X3DhPrivkeyBundle {
        // The default() method does actual key generation here
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

/// To encap, we need the recipient's public keys and the sender's private key
struct EncapContext(X3DhPubkeyBundle, IdentityKey);

/// To decap, we need the recipient's private keys and the sender's public key
struct DecapContext(X3DhPrivkeyBundle, IdentityKey);

// Define an authenticated encapsulator. To authenticate, we need a full sender keypair.
impl Encapsulate<EphemeralKey, SharedSecret> for EncapContext {
    type Error = &'static str;

    fn encapsulate(
        &self,
        _: &mut impl CryptoRngCore,
    ) -> Result<(EphemeralKey, SharedSecret), Self::Error> {
        // Make a new ephemeral key. This will be the encapped key
        let ek = EphemeralKey::default();
        // Deconstruct the recipient's pubkey bundle
        let X3DhPubkeyBundle {
            ref ik,
            ref spk,
            ref sig,
            ref opk,
        } = self.0;
        let my_ik = &self.1;

        // Do the X3DH operation to get the shared secret
        let shared_secret = x3dh_a(sig, my_ik, spk, &ek, ik, opk)?;

        Ok((ek, shared_secret))
    }
}

// Define an decapsulator. Since authenticated and unauthenticated encapped keys are represented by
// the same type (which, outside of testing, should not be the case), this can do both auth'd and
// unauth'd decapsulation.
impl Decapsulate<EphemeralKey, SharedSecret> for DecapContext {
    // TODO: Decapsulation is infallible. Make the Error type `!` when it's stable.
    type Error = ();

    fn decapsulate(&self, ek: &EphemeralKey) -> Result<SharedSecret, Self::Error> {
        // Deconstruct our private keys bundle
        let X3DhPrivkeyBundle {
            ref ik,
            ref spk,
            ref opk,
            ..
        } = self.0;
        let sender_pubkey = &self.1;

        // Now decapsulate
        Ok(x3dh_b(sender_pubkey, spk, ek, ik, opk))
    }
}

#[test]
fn test_x3dh() {
    let mut rng = rand::thread_rng();

    // We use _a and _b suffixes to denote whether a key belongs to Alice or Bob. Alice is the
    // sender in this case.
    let sk_ident_a = IdentityKey::default();
    let pk_ident_a = sk_ident_a.strip();
    let sk_bundle_b = X3DhPrivkeyBundle::gen();
    let pk_bundle_b = sk_bundle_b.as_pubkeys();

    let encap_context = EncapContext(pk_bundle_b, sk_ident_a);
    let decap_context = DecapContext(sk_bundle_b, pk_ident_a);

    // Now do an authenticated encap
    let (encapped_key, ss1) = encap_context.encapsulate(&mut rng).unwrap();
    let ss2 = decap_context.decapsulate(&encapped_key).unwrap();
    assert_eq!(ss1, ss2);
}
