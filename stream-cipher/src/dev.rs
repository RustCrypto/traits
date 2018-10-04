/// Test core functionality of stream cipher, i.e
/// `StreamCipherCore::apply_keystream` method
#[macro_export]
macro_rules! new_core_test {
    ($name:ident, $cipher:ty, $test_name:expr) => {
        #[test]
        fn $name() {
            use stream_cipher::generic_array::GenericArray;
            use stream_cipher::{StreamCipherCore, NewFixStreamCipher};
            use stream_cipher::blobby::Blob4Iterator;

            let data = include_bytes!(concat!("data/", $test_name, ".blb"));
            for (i, row) in Blob4Iterator::new(data).unwrap().enumerate() {
                let key = GenericArray::from_slice(row[0]);
                let iv = GenericArray::from_slice(row[1]);
                let plaintext = row[2];
                let ciphertext = row[3];

                for chunk_n in 1..256 {
                    let mut mode = <$cipher>::new(key, iv);
                    let mut pt = plaintext.to_vec();
                    for chunk in pt.chunks_mut(chunk_n) {
                        mode.apply_keystream(chunk);
                    }
                    if pt != &ciphertext[..] {
                        panic!("Failed main test №{}, chunk size: {}\n\
                            key:\t{:?}\n\
                            iv:\t{:?}\n\
                            plaintext:\t{:?}\n\
                            ciphertext:\t{:?}\n",
                            i, chunk_n, key, iv, plaintext, ciphertext,
                        );
                    }
                }
            }
        }
    }
}

/// Test stream cipher seeking capabilities, i.e. `StreamCipherSeek::seek`
/// method
#[macro_export]
macro_rules! new_seek_test {
    ($name:ident, $cipher:ty, $test_name:expr) => {
        #[test]
        fn $name() {
            use stream_cipher::generic_array::GenericArray;
            use stream_cipher::{
                StreamCipherCore, StreamCipherSeek, NewFixStreamCipher
            };
            use stream_cipher::blobby::Blob4Iterator;

            let data = include_bytes!(concat!("data/", $test_name, ".blb"));
            for (i, row) in Blob4Iterator::new(data).unwrap().enumerate() {
                let key =  GenericArray::from_slice(row[0]);
                let iv =  GenericArray::from_slice(row[1]);
                let plaintext = row[2];
                let ciphertext = row[3];

                let mut mode = <$cipher>::new(key, iv);
                for seek_n in 0..512 {
                    let mut pt = plaintext[seek_n..].to_vec();
                    mode.seek(seek_n as u64);
                    mode.apply_keystream(&mut pt);
                    if pt != &ciphertext[seek_n..] {
                        panic!("Failed seek test №{}, seek pos: {}\n\
                            key:\t{:?}\n\
                            iv:\t{:?}\n\
                            plaintext:\t{:?}\n\
                            ciphertext:\t{:?}\n",
                            i, seek_n, key, iv, plaintext, ciphertext,
                        );
                    }
                }
            }
        }
    }
}

/// Create benchmarks for NewFixStreamCipher implementors
#[macro_export]
macro_rules! bench_fixed {
    ($name:ident, $cipher:path, $data_len:expr) => {
        #[bench]
        pub fn $name(bh: &mut Bencher) {
            let key = Default::default();
            let nonce = Default::default();
            let mut cipher = <$cipher>::new(&key, &nonce);
            let mut data = [77; $data_len];

            bh.iter(|| {
                cipher.apply_keystream(&mut data);
                test::black_box(&data);
            });
            bh.bytes = data.len() as u64;
        }
    };
    ($cipher:path) => {
        extern crate test;

        use test::Bencher;
        use stream_cipher::generic_array::GenericArray;
        use stream_cipher::{StreamCipherCore, NewFixStreamCipher};

        bench_fixed!(bench1_10,     $cipher, 10);
        bench_fixed!(bench2_100,    $cipher, 100);
        bench_fixed!(bench3_1000,   $cipher, 1000);
        bench_fixed!(bench4_10000 , $cipher, 10000);
        bench_fixed!(bench5_100000, $cipher, 100000);
    }
}
