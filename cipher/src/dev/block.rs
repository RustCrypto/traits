//! Development-related functionality for block ciphers

use crate::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};

/// Block cipher test vector
#[derive(Debug, Clone, Copy)]
pub struct TestVector {
    /// Initialization key
    pub key: &'static [u8],
    /// Plaintext block
    pub plaintext: &'static [u8],
    /// Ciphertext block
    pub ciphertext: &'static [u8],
}

fn encrypt_test_inner<C: BlockCipherEncrypt>(
    cipher: &C,
    pt: Block<C>,
    ct: Block<C>,
) -> Result<(), &'static str> {
    let mut block = pt.clone();
    cipher.encrypt_block(&mut block);
    if block != ct {
        return Err("single block encryption failure");
    }

    let mut blocks1: [Block<C>; 101] = core::array::from_fn(|i| {
        let mut block = pt.clone();
        block[0] ^= i as u8;
        block
    });
    let mut blocks2 = blocks1.clone();

    // Check that `encrypt_blocks` and `encrypt_block` result in the same ciphertext
    cipher.encrypt_blocks(&mut blocks1);
    for b in blocks2.iter_mut() {
        cipher.encrypt_block(b);
    }
    if blocks1 != blocks2 {
        return Err("multi-block encryption failure");
    }

    Ok(())
}

fn decrypt_test_inner<C: BlockCipherDecrypt>(
    cipher: &C,
    pt: Block<C>,
    ct: Block<C>,
) -> Result<(), &'static str> {
    let mut block = ct.clone();
    cipher.decrypt_block(&mut block);
    if block != pt {
        return Err("single block decryption failure");
    }

    let mut blocks1: [Block<C>; 101] = core::array::from_fn(|i| {
        let mut block = ct.clone();
        block[0] ^= i as u8;
        block
    });
    let mut blocks2 = blocks1.clone();

    // Check that `encrypt_blocks` and `encrypt_block` result in the same ciphertext
    cipher.decrypt_blocks(&mut blocks1);
    for b in blocks2.iter_mut() {
        cipher.decrypt_block(b);
    }
    if blocks1 != blocks2 {
        return Err("multi-block decryption failure");
    }
    Ok(())
}

/// Block cipher encryption and decryption test
pub fn encrypt_decrypt_test<C: BlockCipherEncrypt + BlockCipherDecrypt + KeyInit>(
    tv: &TestVector,
) -> Result<(), &'static str> {
    let Ok(cipher) = C::new_from_slice(tv.key) else {
        return Err("cipher initialization failure");
    };

    let Ok(pt) = Block::<C>::try_from(tv.plaintext) else {
        return Err("unexpected size of plaintext block");
    };
    let Ok(ct) = Block::<C>::try_from(tv.ciphertext) else {
        return Err("unexpected size of ciphertext block");
    };

    encrypt_test_inner(&cipher, pt.clone(), ct.clone())?;
    decrypt_test_inner(&cipher, pt, ct)
}

/// Block cipher encryption test
pub fn encrypt_test<C: BlockCipherEncrypt + KeyInit>(tv: &TestVector) -> Result<(), &'static str> {
    let Ok(cipher) = C::new_from_slice(tv.key) else {
        return Err("cipher initialization failure");
    };

    let Ok(pt) = Block::<C>::try_from(tv.plaintext) else {
        return Err("unexpected size of plaintext block");
    };
    let Ok(ct) = Block::<C>::try_from(tv.ciphertext) else {
        return Err("unexpected size of ciphertext block");
    };

    encrypt_test_inner(&cipher, pt, ct)
}

/// Block cipher encryption test
pub fn decrypt_test<C: BlockCipherDecrypt + KeyInit>(tv: &TestVector) -> Result<(), &'static str> {
    let Ok(cipher) = C::new_from_slice(tv.key) else {
        return Err("cipher initialization failure");
    };
    let Ok(pt) = Block::<C>::try_from(tv.plaintext) else {
        return Err("unexpected size of plaintext block");
    };
    let Ok(ct) = Block::<C>::try_from(tv.ciphertext) else {
        return Err("unexpected size of ciphertext block");
    };
    decrypt_test_inner(&cipher, pt, ct)
}

/// Define block cipher test
#[macro_export]
macro_rules! block_cipher_test {
    // Encrypt/decrypt test with matching test and file names
    ($name:ident, $cipher:ty $(,)?) => {
        $crate::block_cipher_test!($name, stringify!($name), $cipher);
    };
    // Encrypt/decrypt test with custom test name
    ($test_name:ident, $file_name:expr, $cipher:ty $(,)?) => {
        $crate::block_cipher_test!($test_name, $file_name, $cipher, encrypt_decrypt_test);
    };
    // Test with custom test function and matching test and file names
    ($name:ident, $cipher:ty, $test_fn:ident $(,)?) => {
        $crate::block_cipher_test!($name, stringify!($name), $cipher, $test_fn);
    };
    // Test with custom test function and test name
    ($test_name:ident, $file_name:expr, $cipher:ty, $test_fn:ident $(,)?) => {
        #[test]
        fn $test_name() {
            use $crate::dev::block::TestVector;

            $crate::dev::blobby::parse_into_structs!(
                include_bytes!(concat!("data/", $file_name, ".blb"));
                static TEST_VECTORS: &[
                    TestVector { key, plaintext, ciphertext }
                ];
            );

            for (i, tv) in TEST_VECTORS.iter().enumerate() {
                if let Err(reason) = $crate::dev::block::$test_fn::<$cipher>(tv) {
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

/// Define block encryptor benchmark
#[macro_export]
macro_rules! block_encryptor_bench {
    (Key: $cipher:ty, $block_name:ident, $blocks_name:ident $(,)? ) => {
        $crate::block_encryptor_bench!(
            {
                use $crate::KeyInit;
                let key = test::black_box(Default::default());
                <$cipher>::new(&key)
            },
            $cipher,
            $block_name,
            $blocks_name,
        );
    };
    (KeyIv: $cipher:ty, $block_name:ident, $blocks_name:ident $(,)? ) => {
        $crate::block_encryptor_bench!(
            {
                use $crate::KeyIvInit;
                let key = test::black_box(Default::default());
                let iv = test::black_box(Default::default());
                <$cipher>::new(&key, &iv)
            },
            $cipher,
            $block_name,
            $blocks_name,
        );
    };
    ($init:block, $cipher:ty, $block_name:ident, $blocks_name:ident $(,)? ) => {
        #[bench]
        pub fn $block_name(bh: &mut test::Bencher) {
            #[allow(unused)]
            use $crate::{BlockCipherEncrypt, BlockModeEncrypt};

            let mut cipher = $init;
            let mut blocks = vec![Default::default(); 1024];

            bh.iter(|| {
                for block in blocks.iter_mut() {
                    cipher.encrypt_block(block);
                }
                test::black_box(&blocks);
            });
            bh.bytes = (blocks.len() * blocks[0].len()) as u64;
        }

        #[bench]
        pub fn $blocks_name(bh: &mut test::Bencher) {
            #[allow(unused)]
            use $crate::{BlockCipherEncrypt, BlockModeEncrypt};

            let mut cipher = $init;
            let mut blocks = vec![Default::default(); 1024];

            bh.iter(|| {
                cipher.encrypt_blocks(&mut blocks);
                test::black_box(&blocks);
            });
            bh.bytes = (blocks.len() * blocks[0].len()) as u64;
        }
    };
}

/// Define block decryptor benchmark
#[macro_export]
macro_rules! block_decryptor_bench {
    (Key: $cipher:ty, $block_name:ident, $blocks_name:ident $(,)? ) => {
        $crate::block_decryptor_bench!(
            {
                use $crate::KeyInit;
                let key = test::black_box(Default::default());
                <$cipher>::new(&key)
            },
            $cipher,
            $block_name,
            $blocks_name,
        );
    };
    (KeyIv: $cipher:ty, $block_name:ident, $blocks_name:ident $(,)? ) => {
        $crate::block_decryptor_bench!(
            {
                use $crate::KeyIvInit;
                let key = test::black_box(Default::default());
                let iv = test::black_box(Default::default());
                <$cipher>::new(&key, &iv)
            },
            $cipher,
            $block_name,
            $blocks_name,
        );
    };
    ($init:block, $cipher:ty, $block_name:ident, $blocks_name:ident $(,)? ) => {
        #[bench]
        pub fn $block_name(bh: &mut test::Bencher) {
            #[allow(unused)]
            use $crate::{BlockCipherDecrypt, BlockModeDecrypt};

            let mut cipher = $init;
            let mut blocks = vec![Default::default(); 1024];

            bh.iter(|| {
                for block in blocks.iter_mut() {
                    cipher.decrypt_block(block);
                }
                test::black_box(&blocks);
            });
            bh.bytes = (blocks.len() * blocks[0].len()) as u64;
        }

        #[bench]
        pub fn $blocks_name(bh: &mut test::Bencher) {
            #[allow(unused)]
            use $crate::{BlockCipherDecrypt, BlockModeDecrypt};

            let mut cipher = $init;
            let mut blocks = vec![Default::default(); 1024];

            bh.iter(|| {
                cipher.decrypt_blocks(&mut blocks);
                test::black_box(&blocks);
            });
            bh.bytes = (blocks.len() * blocks[0].len()) as u64;
        }
    };
}
