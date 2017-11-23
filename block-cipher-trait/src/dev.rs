
#[macro_export]
macro_rules! new_test {
    ($name:ident, $test_name:expr, $cipher:ty) => {
        #[test]
        fn $name() {
            use des::BlockCipher;
            use block_cipher_trait::generic_array::GenericArray;

            fn run_test(key: &[u8], pt: &[u8], ct: &[u8]) -> bool {
                let state = <$cipher as BlockCipher>::new_varkey(key).unwrap();

                let mut block = GenericArray::clone_from_slice(pt);
                state.encrypt_block(&mut block);
                if ct != block.as_slice() {
                    return false;
                }

                state.decrypt_block(&mut block);
                if pt != block.as_slice() {
                    return false;
                }
                true
            }

            let keys = include_bytes!(
                concat!("data/", $test_name, ".keys.bin"));
            let plaintexts = include_bytes!(
                concat!("data/", $test_name, ".plaintexts.bin"));
            let ciphertexts = include_bytes!(
                concat!("data/", $test_name, ".ciphertexts.bin"));
            let index = include_bytes!(
                concat!("data/", $test_name, ".index.bin"));
            // u32 (2 bytes); start + end (x2); key, plaintext, ciphertext (x3)
            assert_eq!(index.len() % (2*3*2), 0, "invlaid index length");
            for (i, chunk) in index.chunks(2*3*2).enumerate() {
                // proper aligment is assumed here
                let idx = unsafe {
                    &*(chunk.as_ptr() as *const [[u16; 2]; 3])
                };
                let key = &keys[(idx[0][0] as usize)..(idx[0][1] as usize)];
                let plaintext = &plaintexts[
                    (idx[1][0] as usize)..(idx[1][1] as usize)];
                let ciphertext = &ciphertexts[
                    (idx[2][0] as usize)..(idx[2][1] as usize)];
                if !run_test(key, plaintext, ciphertext) {
                    panic!("\n\
                        Failed test №{}\n\
                        key: [{}..{}]\t{:?}\n\
                        plaintext: [{}..{}]\t{:?}\n\
                        ciphertext: [{}..{}]\t{:?}\n",
                        i, idx[0][0], idx[0][1], key,
                        idx[1][0], idx[1][1], plaintext,
                        idx[2][0], idx[2][1], ciphertext,
                    );
                }

            }
        }
    }
}

#[macro_export]
macro_rules! bench {
    ($cipher:path, $key_len:expr) => {
        extern crate test;

        use test::Bencher;
        use block_cipher_trait::BlockCipher;

        #[bench]
        pub fn encrypt(bh: &mut Bencher) {
            let state = <$cipher>::new_varkey(&[1u8; $key_len]).unwrap();
            let mut block = Default::default();

            bh.iter(|| {
                state.encrypt_block(&mut block);
                test::black_box(&block);
            });
            bh.bytes = block.len() as u64;
        }

        #[bench]
        pub fn decrypt(bh: &mut Bencher) {
            let state = <$cipher>::new_varkey(&[1u8; $key_len]).unwrap();
            let mut block = Default::default();

            bh.iter(|| {
                state.decrypt_block(&mut block);
                test::black_box(&block);
            });
            bh.bytes = block.len() as u64;
        }
    }
}
