//! Development-related functionality

pub use blobby;

use crate::Aead;
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
///
/// # Errors
/// - If the cipher has failed initialization with the provided key.
/// - If the AEAD mode has failed to pass the test vector.
pub fn pass_test<C: Aead + KeyInit>(
    &TestVector {
        key,
        nonce,
        aad,
        plaintext,
        ciphertext,
    }: &TestVector,
) -> Result<(), &'static str> {
    let cipher: C = KeyInit::new_from_slice(key).map_err(|_| "failed to initialize the cipher")?;

    let res = cipher
        .encrypt_into_vec(nonce, aad, plaintext)
        .map_err(|_| "encryption failure")?;
    if res != ciphertext {
        return Err("encrypted data is different from target ciphertext");
    }

    let res = cipher
        .decrypt_into_vec(nonce, aad, ciphertext)
        .map_err(|_| "decryption failure")?;
    if res != plaintext {
        return Err("decrypted data is different from target plaintext");
    }

    let mut buf = ciphertext.to_vec();

    // Flip one bit
    buf[0] ^= 1;

    let res = cipher.decrypt_within_vec(nonce, aad, &mut buf);

    if res.is_ok() {
        return Err("did not detect corrupted ciphertext");
    }
    if buf.iter().any(|&b| b != 0) {
        return Err("the buffer was not zeroized after failure");
    }

    Ok(())
}

/// Run AEAD test for the provided failing test vector
///
/// # Errors
/// - If the cipher has failed initialization with the provided key.
/// - If the cipher has passed the test vector.
pub fn fail_test<C: Aead + KeyInit>(
    &TestVector {
        key,
        nonce,
        aad,
        ciphertext,
        ..
    }: &TestVector,
) -> Result<(), &'static str> {
    let cipher: C = KeyInit::new_from_slice(key).map_err(|_| "failed to initialize the cipher")?;

    let res = cipher.decrypt_into_vec(nonce, aad, ciphertext);
    if res.is_ok() {
        return Err("decryption must return error");
    }

    let mut buf = ciphertext.to_vec();
    let res = cipher.decrypt_within_vec(nonce, aad, &mut buf);

    if res.is_ok() {
        return Err("decryption must return error");
    }
    if buf.iter().any(|&b| b != 0) {
        return Err("the buffer was not zeroized after failure");
    }

    Ok(())
}

/// Define AEAD test for passing test vectors
#[macro_export]
macro_rules! new_pass_test {
    ($name:ident, $cipher:ty $(,)?) => {
        $crate::new_pass_test!($name, stringify!($name), $cipher);
    };
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
    ($name:ident, $cipher:ty $(,)?) => {
        $crate::new_fail_test!($name, stringify!($name), $cipher);
    };
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
