use generic_array::GenericArray;

use super::{NewVarKey, BlockCipher};

pub struct Test {
    pub name: &'static str,
    pub key: &'static [u8],
    pub input: &'static [u8],
    pub output: &'static [u8],
}

#[macro_export]
macro_rules! new_block_cipher_tests {
    ( $( $name:expr ),*  ) => {
        [$(
            BlockCipherTest {
                name: $name,
                key: include_bytes!(concat!("data/", $name, ".key.bin")),
                input: include_bytes!(concat!("data/", $name, ".input.bin")),
                output: include_bytes!(concat!("data/", $name, ".output.bin")),
            },
        )*]
    };
}

pub fn encrypt_decrypt<B: NewVarKey + BlockCipher>(tests: &[BlockCipherTest]) {
    // test encryption
    for test in tests {
        let state = B::new(test.key).unwrap();
        let mut block = GenericArray::clone_from_slice(test.input);
        state.encrypt_block(&mut block);
        assert_eq!(test.output, block.as_slice());
    }

    // test decription
    for test in tests {
        let state = B::new(test.key).unwrap();
        let mut block = GenericArray::clone_from_slice(test.output);
        state.decrypt_block(&mut block);
        assert_eq!(test.input, block.as_slice());
    }
}

#[macro_export]
macro_rules! bench_block_cipher {
    ($cipher:path, $key_len:expr) => {
        extern crate test;

        use test::Bencher;
        use block_cipher_trait::{BlockCipher, NewVarKey};

        #[bench]
        pub fn encrypt(bh: &mut Bencher) {
            let state = <$cipher>::new(&[1u8; $key_len]).unwrap();
            let mut block = Default::default();

            bh.iter(|| {
                state.encrypt_block(&mut block);
                test::black_box(&block);
            });
            bh.bytes = block.len() as u64;
        }

        #[bench]
        pub fn decrypt(bh: &mut Bencher) {
            let state = <$cipher>::new(&[1u8; $key_len]).unwrap();
            let mut block = Default::default();

            bh.iter(|| {
                state.decrypt_block(&mut block);
                test::black_box(&block);
            });
            bh.bytes = block.len() as u64;
        }
    }
}
