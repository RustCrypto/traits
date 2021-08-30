//! Development-related functionality

pub use blobby;

/// Define block cipher test
#[macro_export]
#[cfg_attr(docsrs, doc(cfg(feature = "dev")))]
macro_rules! block_cipher_test {
    ($name:ident, $test_name:expr, $cipher:ty) => {
        #[test]
        fn $name() {
            use cipher::generic_array::{typenum::Unsigned, GenericArray};
            use cipher::{
                blobby::Blob3Iterator, BlockDecryptMut, BlockEncryptMut, BlockUser, KeyInit,
            };

            fn run_test(key: &[u8], pt: &[u8], ct: &[u8]) -> bool {
                let mut state = <$cipher as KeyInit>::new_from_slice(key).unwrap();

                let mut block = GenericArray::clone_from_slice(pt);
                state.encrypt_block_mut(&mut block);
                if ct != block.as_slice() {
                    return false;
                }

                state.decrypt_block_mut(&mut block);
                if pt != block.as_slice() {
                    return false;
                }

                true
            }

            fn run_par_test(key: &[u8], pt: &[u8]) -> bool {
                type Block = cipher::Block<$cipher>;

                let mut state = <$cipher as KeyInit>::new_from_slice(key).unwrap();

                let block = Block::clone_from_slice(pt);
                let mut blocks1 = vec![block; 101];
                for (i, b) in blocks1.iter_mut().enumerate() {
                    *b = block;
                    b[0] = b[0].wrapping_add(i as u8);
                }
                let mut blocks2 = blocks1.clone();

                // check that `encrypt_blocks` and `encrypt_block`
                // result in the same ciphertext
                state.encrypt_blocks_mut(&mut blocks1, |_| {});
                for b in blocks2.iter_mut() {
                    state.encrypt_block_mut(b);
                }
                if blocks1 != blocks2 {
                    return false;
                }

                // check that `encrypt_blocks` and `encrypt_block`
                // result in the same plaintext
                state.decrypt_blocks_mut(&mut blocks1, |_| {});
                for b in blocks2.iter_mut() {
                    state.decrypt_block_mut(b);
                }
                if blocks1 != blocks2 {
                    return false;
                }

                true
            }

            let data = include_bytes!(concat!("data/", $test_name, ".blb"));
            for (i, row) in Blob3Iterator::new(data).unwrap().enumerate() {
                let [key, pt, ct] = row.unwrap();
                if !run_test(key, pt, ct) {
                    panic!(
                        "\n\
                         Failed test №{}\n\
                         key:\t{:?}\n\
                         plaintext:\t{:?}\n\
                         ciphertext:\t{:?}\n",
                        i, key, pt, ct,
                    );
                }

                // test parallel blocks encryption/decryption
                if !run_par_test(key, pt) {
                    panic!(
                        "\n\
                         Failed parallel test №{}\n\
                         key:\t{:?}\n\
                         plaintext:\t{:?}\n\
                         ciphertext:\t{:?}\n",
                        i, key, pt, ct,
                    );
                }
            }
        }
    };
}

/// Define block encryptor benchmark
#[macro_export]
#[cfg_attr(docsrs, doc(cfg(feature = "dev")))]
macro_rules! block_encryptor_bench {
    ($cipher:path, $block_name:ident, $blocks_name:ident $(,)? ) => {
        #[bench]
        pub fn $block_name(bh: &mut test::Bencher) {
            use cipher::{BlockEncryptMut, KeyInit};

            let key = Default::default();
            let mut cipher = test::black_box(<$cipher>::new(&key));
            let mut block = Default::default();

            bh.iter(|| {
                cipher.encrypt_block_mut(&mut block);
                test::black_box(&block);
            });
            bh.bytes = block.len() as u64;
        }

        #[bench]
        pub fn $blocks_name(bh: &mut test::Bencher) {
            use cipher::{BlockEncryptMut, KeyInit};

            let key = Default::default();
            let mut cipher = test::black_box(<$cipher>::new(&key));
            let mut blocks = vec![Default::default(); 16 * 1024];

            bh.iter(|| {
                cipher.encrypt_blocks_mut(&mut blocks, |_| {});
                test::black_box(&blocks);
            });
            bh.bytes = (blocks.len() * blocks[0].len()) as u64;
        }
    };
}

/// Define block decryptor benchmark
#[macro_export]
#[cfg_attr(docsrs, doc(cfg(feature = "dev")))]
macro_rules! block_decryptor_bench {
    ($cipher:path, $block_name:ident, $blocks_name:ident $(,)? ) => {
        #[bench]
        pub fn $block_name(bh: &mut test::Bencher) {
            use cipher::{BlockEncryptMut, KeyInit};

            let key = Default::default();
            let mut cipher = test::black_box(<$cipher>::new(&key));
            let mut block = Default::default();

            bh.iter(|| {
                cipher.encrypt_block_mut(&mut block);
                test::black_box(&block);
            });
            bh.bytes = block.len() as u64;
        }

        #[bench]
        pub fn $blocks_name(bh: &mut test::Bencher) {
            use cipher::{BlockEncryptMut, KeyInit};

            let key = Default::default();
            let mut cipher = test::black_box(<$cipher>::new(&key));
            let mut blocks = vec![Default::default(); 16 * 1024];

            bh.iter(|| {
                cipher.encrypt_blocks_mut(&mut blocks, |_| {});
                test::black_box(&blocks);
            });
            bh.bytes = (blocks.len() * blocks[0].len()) as u64;
        }
    };
}
