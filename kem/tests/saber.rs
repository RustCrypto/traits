#[cfg(test)]
mod tests {
    use generic_array::{typenum::U32, GenericArray};
    use kem::{Decapsulator, EncappedKey, Encapsulator, Error};
    use pqcrypto::kem::firesaber::{
        decapsulate, encapsulate, keypair, Ciphertext, PublicKey, SecretKey,
    };
    use pqcrypto_traits::kem::{Ciphertext as CiphertextTrait, SharedSecret as SharedSecretTrait};
    use rand::rngs::OsRng;
    use rand_core::{CryptoRng, RngCore};

    // Define the pubkey type. This has no trait bounds required by the library
    type SaberPublicKey = PublicKey;

    // The encapped key type is called "Ciphertext" in Rust's pqcrypto. Impl the necessary traits.
    struct SaberEncappedKey(Ciphertext);
    impl EncappedKey for SaberEncappedKey {
        type NSecret = U32;
        // In HPKE the only recipient public key is the identity key
        type RecipPublicKey = SaberPublicKey;
        // The sender's pubkey is the identity too
        type SenderPublicKey = SaberPrivateKey;
    }
    impl AsRef<[u8]> for SaberEncappedKey {
        fn as_ref(&self) -> &[u8] {
            self.0.as_bytes()
        }
    }
    impl core::fmt::Debug for SaberEncappedKey {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            write!(f, "{:x?}", self.as_ref())
        }
    }

    // Define some convenience types
    type SaberSharedSecret = GenericArray<u8, <SaberEncappedKey as EncappedKey>::NSecret>;
    type SaberPrivateKey = SecretKey;

    // Define an unauthenticated encapsulator. It holds nothing at all
    struct SaberEncapper;
    impl Encapsulator<SaberEncappedKey> for SaberEncapper {
        fn try_encap<R: RngCore + CryptoRng>(
            &self,
            _csprng: &mut R,
            recip_pubkey: &SaberPublicKey,
        ) -> Result<(SaberEncappedKey, SaberSharedSecret), Error> {
            let (ss, ek) = encapsulate(recip_pubkey);
            let ss_bytes = SaberSharedSecret::clone_from_slice(ss.as_bytes());

            Ok((SaberEncappedKey(ek), ss_bytes))
        }
    }

    // Define a decapsulator
    impl Decapsulator<SaberEncappedKey> for SaberPrivateKey {
        fn try_decap(&self, encapped_key: &SaberEncappedKey) -> Result<SaberSharedSecret, Error> {
            let ss = decapsulate(&encapped_key.0, self);
            Ok(SaberSharedSecret::clone_from_slice(ss.as_bytes()))
        }
    }

    #[test]
    fn test_saber() {
        let mut rng = OsRng;

        // Make a recipient keypair
        let (pk_recip, sk_recip) = keypair();

        // Do an unauthed encap. Check that the derived shared secrets are equal
        let encapper = SaberEncapper;
        let (ek, ss1) = encapper.try_encap(&mut rng, &pk_recip).unwrap();
        let ss2 = sk_recip.try_decap(&ek).unwrap();
        assert_eq!(ss1, ss2);
    }
}
