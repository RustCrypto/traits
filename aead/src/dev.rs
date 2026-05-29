//! Development-related functionality

#![allow(clippy::missing_errors_doc, reason = "dev module")]
#![allow(clippy::missing_panics_doc, reason = "dev module")]
#![allow(clippy::unwrap_in_result, reason = "dev module")]

use crate::{Aead, Payload};
pub use blobby;
use common::KeyInit;

/// AEAD test vector
#[derive(Debug, Clone, Copy)]
pub struct TestVector {
    /// Initialization key
    pub key: &'static [u8],
    /// Nonce
    pub nonce: &'static [u8],
    /// Additional associated data
    pub aad: &'static [u8],
    /// Plaintext
    pub plaintext: &'static [u8],
    /// Ciphertext
    pub ciphertext: &'static [u8],
}

/// Run AEAD test for the provided passing test vector
#[allow(clippy::cast_possible_truncation)]
pub fn pass_test<C: Aead + KeyInit>(
    &TestVector {
        key,
        nonce,
        aad,
        plaintext,
        ciphertext,
    }: &TestVector,
) -> Result<(), &'static str> {
    let cipher = <C as KeyInit>::new_from_slice(key).expect("failed to initialize the cipher");

    let res = cipher
        .encrypt(Payload {
            nonce,
            aad,
            msg: plaintext,
        })
        .map_err(|_| "encryption failure")?;
    if res != ciphertext {
        return Err("encrypted data is different from target ciphertext");
    }

    let res = cipher
        .decrypt(Payload {
            nonce,
            aad,
            msg: ciphertext,
        })
        .map_err(|_| "decryption failure")?;
    if res != plaintext {
        return Err("decrypted data is different from target plaintext");
    }

    Ok(())
}

/// Run AEAD test for the provided failing test vector
pub fn fail_test<C: Aead + KeyInit>(
    &TestVector {
        key,
        nonce,
        aad,
        ciphertext,
        ..
    }: &TestVector,
) -> Result<(), &'static str> {
    let cipher = <C as KeyInit>::new_from_slice(key).expect("failed to initialize the cipher");

    let res = cipher.decrypt(Payload {
        nonce,
        aad,
        msg: ciphertext,
    });
    if res.is_ok() {
        Err("decryption must return error")
    } else {
        Ok(())
    }
}

/// Define AEAD test for passing test vectors
#[macro_export]
macro_rules! new_pass_test {
    ($name:ident, $test_name:expr, $cipher:ty $(,)?) => {
        #[test]
        fn $name() {
            use $crate::dev::TestVector;

            $crate::dev::blobby::parse_into_structs!(
                include_bytes!(concat!("data/", $test_name, ".blb"));
                static TEST_VECTORS: &[
                    TestVector { key, nonce, aad, plaintext, ciphertext }
                ];
            );

            for (i, tv) in TEST_VECTORS.iter().enumerate() {
                let res = $crate::dev::pass_test::<$cipher>(tv);

                if let Err(reason) = res {
                    panic!(
                        "\n\
                        Failed test #{i}\n\
                        reason:\t{reason:?}\n\
                        test vector:\t{tv:?}\n"
                    );
                }
            }
        }
    };
}

/// Define AEAD test for failing test vectors
#[macro_export]
macro_rules! new_fail_test {
    ($name:ident, $test_name:expr, $cipher:ty $(,)?) => {
        #[test]
        fn $name() {
            use $crate::dev::TestVector;

            $crate::dev::blobby::parse_into_structs!(
                include_bytes!(concat!("data/", $test_name, ".blb"));
                static TEST_VECTORS: &[
                    TestVector { key, nonce, aad, plaintext, ciphertext }
                ];
            );

            for (i, tv) in TEST_VECTORS.iter().enumerate() {
                let res = $crate::dev::fail_test::<$cipher>(tv);

                if let Err(reason) = res {
                    panic!(
                        "\n\
                        Failed test #{i}\n\
                        reason:\t{reason:?}\n\
                        test vector:\t{tv:?}\n"
                    );
                }
            }
        }
    };
}
