//! Development-related functionality for block modes

#![allow(clippy::missing_errors_doc)]

use crate::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, inout::InOutBuf};

const MAX_MSG_LEN: usize = 1 << 12;

/// Block mode test vector
#[derive(Debug, Clone, Copy)]
pub struct TestVector {
    /// Initialization key
    pub key: &'static [u8],
    /// Initialization vector
    pub iv: &'static [u8],
    /// Plaintext block
    pub plaintext: &'static [u8],
    /// Ciphertext block
    pub ciphertext: &'static [u8],
}

/// Block mode encryption test
pub fn encrypt<C: BlockModeEncrypt + KeyIvInit>(tv: &TestVector) -> Result<(), &'static str> {
    let mut buf = [0u8; MAX_MSG_LEN];
    let Some(out) = buf.get_mut(..tv.ciphertext.len()) else {
        return Err("ciphertext is bigger than MAX_MSG_LEN bytes");
    };
    let Ok(mut buf) = InOutBuf::new(tv.plaintext, out) else {
        return Err("plaintext/ciphertext length mismatch");
    };
    let (blocks, tail) = buf.reborrow().into_chunks();
    if !tail.is_empty() {
        return Err("plaintext/ciphertext length is not multiple of block size");
    }

    let Ok(mut cipher) = C::new_from_slices(tv.key, tv.iv) else {
        return Err("cipher initialization failure");
    };
    for block in blocks {
        cipher.encrypt_block_inout(block);
    }
    if buf.get_out() != tv.ciphertext {
        return Err("single block encryption failure");
    }

    // test multi-block processing
    let Ok(mut cipher) = C::new_from_slices(tv.key, tv.iv) else {
        return Err("cipher initialization failure");
    };
    buf.get_out().fill(0);
    let (blocks, _) = buf.reborrow().into_chunks();
    cipher.encrypt_blocks_inout(blocks);
    if buf.get_out() != tv.ciphertext {
        return Err("multi-block encryption failure");
    }
    Ok(())
}

/// Block mode decryption test
pub fn decrypt<C: BlockModeDecrypt + KeyIvInit>(tv: &TestVector) -> Result<(), &'static str> {
    let mut buf = [0u8; MAX_MSG_LEN];
    let Some(out) = buf.get_mut(..tv.plaintext.len()) else {
        return Err("plaintext is bigger than MAX_MSG_LEN bytes");
    };
    let Ok(mut buf) = InOutBuf::new(tv.ciphertext, out) else {
        return Err("plaintext/ciphertext length mismatch");
    };
    let (blocks, tail) = buf.reborrow().into_chunks();
    if !tail.is_empty() {
        return Err("plaintext/ciphertext length is not multiple of block size");
    }

    let Ok(mut cipher) = C::new_from_slices(tv.key, tv.iv) else {
        return Err("cipher initialization failure");
    };
    for block in blocks {
        cipher.decrypt_block_inout(block);
    }
    if buf.get_out() != tv.plaintext {
        return Err("single block decryption failure");
    }

    // test multi-block processing
    let Ok(mut cipher) = C::new_from_slices(tv.key, tv.iv) else {
        return Err("cipher initialization failure");
    };
    buf.get_out().fill(0);
    let (blocks, _) = buf.reborrow().into_chunks();
    cipher.decrypt_blocks_inout(blocks);
    if buf.get_out() != tv.plaintext {
        return Err("multi-block decryption failure");
    }
    Ok(())
}

/// Define block mode test
#[macro_export]
macro_rules! block_mode_test {
    // Test with matching test and file names
    ($name:ident, $cipher:ty, $test_fn:ident $(,)?) => {
        $crate::block_cipher_test!($name, stringify!($name), $cipher);
    };
    // Test with custom test function and test name
    ($test_name:ident, $file_name:expr, $cipher:ty, $test_fn:ident $(,)?) => {
        #[test]
        fn $test_name() {
            use $crate::dev::block_mode::TestVector;

            $crate::dev::blobby::parse_into_structs!(
                include_bytes!(concat!("data/", $file_name, ".blb"));
                static TEST_VECTORS: &[
                    TestVector { key, iv, plaintext, ciphertext }
                ];
            );

            for (i, tv) in TEST_VECTORS.iter().enumerate() {
                if let Err(reason) = $crate::dev::block_mode::$test_fn::<$cipher>(tv) {
                    panic!(
                        "\n\
                        Failed test #{i}\n\
                        reason:\t{reason:?}\n\
                        test vector:\t{tv:?}\n",
                    );
                }
            }
        }
    };
}

/// Define `IvState` test
#[macro_export]
macro_rules! iv_state_test {
    ($name:ident, $cipher:ty, encrypt $(,)?) => {
        $crate::iv_state_test!($name, $cipher, encrypt_blocks);
    };
    ($name:ident, $cipher:ty, decrypt $(,)?) => {
        $crate::iv_state_test!($name, $cipher, decrypt_blocks);
    };
    ($name:ident, $cipher:ty, apply_ks $(,)?) => {
        $crate::iv_state_test!($name, $cipher, apply_keystream_blocks);
    };
    ($name:ident, $cipher:ty, $method:ident $(,)?) => {
        #[test]
        fn $name() {
            use cipher::*;

            let mut blocks = [Block::<$cipher>::default(); 32];

            for (i, block) in blocks.iter_mut().enumerate() {
                for (j, b) in block.iter_mut().enumerate() {
                    *b = (i + j) as u8;
                }
            }

            let mut key = Key::<$cipher>::default();
            let mut iv = Iv::<$cipher>::default();
            key.iter_mut().for_each(|b| *b = 0x42);
            iv.iter_mut().for_each(|b| *b = 0x24);

            let mut cipher = <$cipher>::new(&key, &iv);
            let mut target = blocks.clone();
            cipher.$method(&mut target);

            for i in 0..32 {
                let mut blocks = blocks.clone();
                let (b1, b2) = blocks.split_at_mut(i);
                let mut cipher1 = <$cipher>::new(&key, &iv);
                cipher1.$method(b1);
                let temp_iv = cipher1.iv_state();
                let mut cipher2 = <$cipher>::new(&key, &temp_iv);
                cipher2.$method(b2);
                assert_eq!(blocks, target);
            }
        }
    };
}
