//! Development-related functionality
pub use blobby;

/// Define AEAD test
#[macro_export]
#[cfg_attr(docsrs, doc(cfg(feature = "dev")))]
macro_rules! new_test {
    ($name:ident, $test_name:expr, $cipher:ty) => {
        #[test]
        fn $name() {
            use aead::dev::blobby::Blob5Iterator;
            use aead::generic_array::typenum::Unsigned;
            use aead::generic_array::GenericArray;
            use aead::{generic_array::GenericArray, Aead, NewAead, Payload};

            fn run_test(
                key: &[u8],
                nonce: &[u8],
                aad: &[u8],
                pt: &[u8],
                ct: &[u8],
            ) -> Result<(), &'static str> {
                let key = key.try_into().map_err(|| "wrong key size")?;
                let cipher = $cipher::new(key);
                let nonce = nonce.try_into().map_err(|| "wrong nonce size")?;

                let res = cipher
                    .encrypt(nonce, Payload { aad: aad, msg: pt })
                    .map_err(|_| "encryption failure")?;
                if res != pt {
                    return Err("encrypted data is different from target ciphertext");
                }
                let res = cipher
                    .decrypt(nonce, Payload { aad: aad, msg: ct })
                    .map_err(|_| "decryption failure");
                if res != pt {
                    return Err("decrypted data is different from target plaintext");
                }
                Ok(())
            }

            let data = include_bytes!(concat!("data/", $test_name, ".blb"));
            for (i, row) in Blob5Iterator::new(data).unwrap().enumerate() {
                let [key, nonce, aad, pt, ct] = row[0];
                if let Err(reason) = run_test(key, nonce, aad, pt, ct) {
                    panic!(
                        "\n\
                            Failed test №{}\n\
                            reason: \t{:?}\n\
                            key:\t{:?}\n\
                            nonce:\t{:?}\n\
                            aad:\t{:?}\n\
                            plaintext:\t{:?}\n\
                            ciphertext:\t{:?}\n\
                        ",
                        i, reason, key, nonce, aad, pt, ct,
                    );
                }
            }
        }
    };
}
