//! Development-related functionality
use crate::{
    Aead, AeadInOut, Nonce, Payload, Tag, TagPosition, array::typenum::Unsigned, inout::InOutBuf,
};
pub use blobby;

/// Run AEAD test for the provided passing test vector
pub fn run_pass_test<C: AeadInOut>(
    cipher: &C,
    nonce: &Nonce<C>,
    aad: &[u8],
    pt: &[u8],
    ct: &[u8],
) -> Result<(), &'static str> {
    let res = cipher
        .encrypt(nonce, Payload { aad, msg: pt })
        .map_err(|_| "encryption failure")?;
    if res != ct {
        return Err("encrypted data is different from target ciphertext");
    }

    let res = cipher
        .decrypt(nonce, Payload { aad, msg: ct })
        .map_err(|_| "decryption failure")?;
    if res != pt {
        return Err("decrypted data is different from target plaintext");
    }

    let (ct, tag) = match C::TAG_POSITION {
        TagPosition::Prefix => {
            let (tag, ct) = ct.split_at(C::TagSize::USIZE);
            (ct, tag)
        }
        TagPosition::Postfix => ct.split_at(pt.len()),
    };
    let tag: &Tag<C> = tag.try_into().expect("tag has correct length");

    // Fill output buffer with "garbage" to test that its data does not get read during encryption
    let mut buf: alloc::vec::Vec<u8> = (0..pt.len()).map(|i| i as u8).collect();
    let inout_buf = InOutBuf::new(pt, &mut buf).expect("pt and buf have the same length");

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
    buf.iter_mut().enumerate().for_each(|(i, v)| *v = i as u8);

    let inout_buf = InOutBuf::new(ct, &mut buf).expect("ct and buf have the same length");
    cipher
        .decrypt_inout_detached(nonce, aad, inout_buf, tag)
        .map_err(|_| "decrypt_inout_detached: decryption failure")?;
    if pt != buf {
        return Err("decrypt_inout_detached: plaintext mismatch");
    }

    Ok(())
}

/// Run AEAD test for the provided failing test vector
pub fn run_fail_test<C: AeadInOut>(
    cipher: &C,
    nonce: &Nonce<C>,
    aad: &[u8],
    ct: &[u8],
) -> Result<(), &'static str> {
    let res = cipher.decrypt(nonce, Payload { aad, msg: ct });
    if res.is_ok() {
        Err("decryption must return error")
    } else {
        Ok(())
    }
}

/// Define AEAD test
#[macro_export]
macro_rules! new_test {
    ($name:ident, $test_name:expr, $cipher:ty $(,)?) => {
        #[test]
        fn $name() {
            use $crate::KeyInit;
            use $crate::dev::blobby::Blob6Iterator;

            let data = include_bytes!(concat!("data/", $test_name, ".blb"));
            for (i, row) in Blob6Iterator::new(data).unwrap().enumerate() {
                let [key, nonce, aad, pt, ct, status] = row.unwrap();
                let key = key.try_into().expect("wrong key size");
                let nonce = nonce.try_into().expect("wrong nonce size");
                let cipher = <$cipher as KeyInit>::new(key);

                let res = match status {
                    [0] => $crate::dev::run_fail_test(&cipher, nonce, aad, ct),
                    [1] => $crate::dev::run_pass_test(&cipher, nonce, aad, pt, ct),
                    _ => panic!("invalid value for pass flag"),
                };
                let mut pass = status[0] == 1;
                if let Err(reason) = res {
                    panic!(
                        "\n\
                        Failed test #{i}\n\
                        reason:\t{reason:?}\n\
                        key:\t{key:?}\n\
                        nonce:\t{nonce:?}\n\
                        aad:\t{aad:?}\n\
                        plaintext:\t{pt:?}\n\
                        ciphertext:\t{ct:?}\n\
                        pass:\t{pass}\n"
                    );
                }
            }
        }
    };
}
