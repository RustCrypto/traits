//! Development-related functionality

#![allow(clippy::missing_errors_doc, reason = "dev module")]
#![allow(clippy::missing_panics_doc, reason = "dev module")]
#![allow(clippy::unwrap_in_result, reason = "dev module")]

use crate::{
    Aead, AeadInOut, Payload, Tag, TagPosition, array::typenum::Unsigned, inout::InOutBuf,
};
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
pub fn pass_test<C: AeadInOut + KeyInit>(
    &TestVector {
        key,
        nonce,
        aad,
        plaintext,
        ciphertext,
    }: &TestVector,
) -> Result<(), &'static str> {
    let nonce = nonce.try_into().expect("wrong nonce size");
    let cipher = <C as KeyInit>::new_from_slice(key).expect("failed to initialize the cipher");

    let res = cipher
        .encrypt(
            nonce,
            Payload {
                aad,
                msg: plaintext,
            },
        )
        .map_err(|_| "encryption failure")?;
    if res != ciphertext {
        return Err("encrypted data is different from target ciphertext");
    }

    let res = cipher
        .decrypt(
            nonce,
            Payload {
                aad,
                msg: ciphertext,
            },
        )
        .map_err(|_| "decryption failure")?;
    if res != plaintext {
        return Err("decrypted data is different from target plaintext");
    }

    let (ct, tag) = match C::TAG_POSITION {
        TagPosition::Prefix => {
            let (tag, ct) = ciphertext.split_at(C::TagSize::USIZE);
            (ct, tag)
        }
        TagPosition::Postfix => ciphertext.split_at(plaintext.len()),
    };
    let tag: &Tag<C> = tag.try_into().expect("tag has correct length");

    // Fill output buffer with "garbage" to test that its data does not get read during encryption
    let mut buf: alloc::vec::Vec<u8> = (0..plaintext.len()).map(|i| i as u8).collect();
    let inout_buf = InOutBuf::new(plaintext, &mut buf).expect("pt and buf have the same length");

    let calc_tag = cipher
        .encrypt_inout_detached(nonce, aad, inout_buf)
        .map_err(|_| "encrypt_inout_detached: encryption failure")?;
    if tag != &calc_tag {
        return Err("encrypt_inout_detached: tag mismatch");
    }
    if ct != buf {
        return Err("encrypt_inout_detached: ciphertext mismatch");
    }

    // Fill output buffer with "garbage"
    buf.iter_mut()
        .enumerate()
        .for_each(|(i, v): (usize, &mut u8)| *v = i as u8);

    let inout_buf = InOutBuf::new(ct, &mut buf).expect("ct and buf have the same length");
    cipher
        .decrypt_inout_detached(nonce, aad, inout_buf, tag)
        .map_err(|_| "decrypt_inout_detached: decryption failure")?;
    if plaintext != buf {
        return Err("decrypt_inout_detached: plaintext mismatch");
    }

    Ok(())
}

/// Run AEAD test for the provided failing test vector
pub fn fail_test<C: AeadInOut + KeyInit>(
    &TestVector {
        key,
        nonce,
        aad,
        ciphertext,
        ..
    }: &TestVector,
) -> Result<(), &'static str> {
    let nonce = nonce.try_into().expect("wrong nonce size");
    let cipher = <C as KeyInit>::new_from_slice(key).expect("failed to initialize the cipher");

    let res = cipher.decrypt(
        nonce,
        Payload {
            aad,
            msg: ciphertext,
        },
    );
    if res.is_ok() {
        return Err("decryption must return error");
    }

    let mut buf = ciphertext.to_vec();
    if cipher.decrypt_in_place(nonce, aad, &mut buf).is_ok() {
        return Err("decrypt_in_place: decryption must return error");
    }
    if buf.len() != ciphertext.len() {
        return Err("decrypt_in_place: buffer length changed on failure");
    }

    // An incomplete tag is rejected before authentication, and cannot be used with the
    // detached API. Only check clearing when the input contains a complete tag.
    let Some(tagless_len) = ciphertext.len().checked_sub(C::TagSize::USIZE) else {
        return Ok(());
    };
    let msg_range = match C::TAG_POSITION {
        TagPosition::Prefix => C::TagSize::USIZE..ciphertext.len(),
        TagPosition::Postfix => 0..tagless_len,
    };
    if buf[msg_range].iter().any(|&b| b != 0) {
        return Err("decrypt_in_place: output buffer was not zeroed");
    }

    let (ct, tag) = match C::TAG_POSITION {
        TagPosition::Prefix => {
            let (tag, ct) = ciphertext.split_at(C::TagSize::USIZE);
            (ct, tag)
        }
        TagPosition::Postfix => ciphertext.split_at(tagless_len),
    };
    let tag: &Tag<C> = tag.try_into().expect("tag has correct length");

    let mut buf = ct.to_vec();
    if cipher
        .decrypt_inout_detached(nonce, aad, buf.as_mut_slice().into(), tag)
        .is_ok()
    {
        return Err("decrypt_inout_detached (in-place): decryption must return error");
    }
    if buf.iter().any(|&b| b != 0) {
        return Err("decrypt_inout_detached (in-place): output buffer was not zeroed");
    }

    // Start with nonzero bytes so that leaving the output untouched cannot pass.
    buf.fill(0xa5);
    let inout_buf = InOutBuf::new(ct, &mut buf).expect("ct and buf have the same length");
    if cipher
        .decrypt_inout_detached(nonce, aad, inout_buf, tag)
        .is_ok()
    {
        return Err("decrypt_inout_detached: decryption must return error");
    }
    if buf.iter().any(|&b| b != 0) {
        return Err("decrypt_inout_detached: output buffer was not zeroed");
    }

    Ok(())
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
