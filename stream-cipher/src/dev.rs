//! Development-related functionality

pub use blobby;

/// Test core functionality of synchronous stream cipher
#[macro_export]
macro_rules! new_sync_test {
    ($name:ident, $cipher:ty, $test_name:expr) => {
        #[test]
        fn $name() {
            use stream_cipher::dev::blobby::Blob4Iterator;
            use stream_cipher::generic_array::GenericArray;
            use stream_cipher::{NewStreamCipher, SyncStreamCipher};

            let data = include_bytes!(concat!("data/", $test_name, ".blb"));
            for (i, row) in Blob4Iterator::new(data).unwrap().enumerate() {
                let key = row[0];
                let iv = row[1];
                let plaintext = row[2];
                let ciphertext = row[3];

                for chunk_n in 1..256 {
                    let mut mode = <$cipher>::new_var(key, iv).unwrap();
                    let mut pt = plaintext.to_vec();
                    for chunk in pt.chunks_mut(chunk_n) {
                        mode.apply_keystream(chunk);
                    }
                    if pt != &ciphertext[..] {
                        panic!(
                            "Failed main test №{}, chunk size: {}\n\
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
    };
}

/// Test stream synchronous stream cipher seeking capabilities
#[macro_export]
macro_rules! new_seek_test {
    ($name:ident, $cipher:ty, $test_name:expr) => {
        #[test]
        fn $name() {
            use stream_cipher::dev::blobby::Blob4Iterator;
            use stream_cipher::generic_array::GenericArray;
            use stream_cipher::{NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek};

            const MAX_SEEK: usize = 512;

            let data = include_bytes!(concat!("data/", $test_name, ".blb"));
            for (i, row) in Blob4Iterator::new(data).unwrap().enumerate() {
                let key = row[0];
                let iv = row[1];
                let plaintext = row[2];
                let ciphertext = row[3];

                let mut mode = <$cipher>::new_var(key, iv).unwrap();
                let pl = plaintext.len();
                let n = if pl > MAX_SEEK { MAX_SEEK } else { pl };
                for seek_n in 0..n {
                    let mut pt = plaintext[seek_n..].to_vec();
                    mode.seek(seek_n as u64);
                    mode.apply_keystream(&mut pt);
                    if pt != &ciphertext[seek_n..] {
                        panic!(
                            "Failed seek test №{}, seek pos: {}\n\
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
    };
}

/// Test core functionality of asynchronous stream cipher
#[macro_export]
macro_rules! new_async_test {
    ($name:ident, $test_name:expr, $cipher:ty) => {
        #[test]
        fn $name() {
            use stream_cipher::dev::blobby::Blob4Iterator;
            use stream_cipher::generic_array::GenericArray;
            use stream_cipher::{NewStreamCipher, StreamCipher};

            fn run_test(
                key: &[u8],
                iv: &[u8],
                plaintext: &[u8],
                ciphertext: &[u8],
            ) -> Option<&'static str> {
                for n in 1..=plaintext.len() {
                    let mut mode = <$cipher>::new_var(key, iv).unwrap();
                    let mut buf = plaintext.to_vec();
                    for chunk in buf.chunks_mut(n) {
                        mode.encrypt(chunk);
                    }
                    if buf != &ciphertext[..] {
                        return Some("encrypt");
                    }
                }

                for n in 1..=plaintext.len() {
                    let mut mode = <$cipher>::new_var(key, iv).unwrap();
                    let mut buf = ciphertext.to_vec();
                    for chunk in buf.chunks_mut(n) {
                        mode.decrypt(chunk);
                    }
                    if buf != &plaintext[..] {
                        return Some("decrypt");
                    }
                }

                None
            }

            let data = include_bytes!(concat!("data/", $test_name, ".blb"));

            for (i, row) in Blob4Iterator::new(data).unwrap().enumerate() {
                let key = row[0];
                let iv = row[1];
                let plaintext = row[2];
                let ciphertext = row[3];
                if let Some(desc) = run_test(key, iv, plaintext, ciphertext) {
                    panic!(
                        "\n\
                         Failed test №{}: {}\n\
                         key:\t{:?}\n\
                         iv:\t{:?}\n\
                         plaintext:\t{:?}\n\
                         ciphertext:\t{:?}\n",
                        i, desc, key, iv, plaintext, ciphertext,
                    );
                }
            }
        }
    };
}

/// Create synchronous stream cipher benchmarks
#[macro_export]
macro_rules! bench_sync {
    ($name:ident, $cipher:path, $data_len:expr) => {
        #[bench]
        pub fn $name(bh: &mut Bencher) {
            let key = Default::default();
            let nonce = Default::default();
            let mut cipher = <$cipher>::new(&key, &nonce);
            let mut data = get_data($data_len);

            bh.iter(|| {
                cipher.apply_keystream(&mut data);
                test::black_box(&data);
            });
            bh.bytes = data.len() as u64;
        }
    };
    ($cipher:path) => {
        extern crate test;

        use stream_cipher::generic_array::GenericArray;
        use stream_cipher::{NewStreamCipher, SyncStreamCipher};
        use test::Bencher;

        #[inline(never)]
        fn get_data(n: usize) -> Vec<u8> {
            vec![77; n]
        }

        bench_sync!(bench1_10, $cipher, 10);
        bench_sync!(bench2_100, $cipher, 100);
        bench_sync!(bench3_1000, $cipher, 1000);
        bench_sync!(bench4_10000, $cipher, 10000);
        bench_sync!(bench5_100000, $cipher, 100000);
    };
}

/// Create synchronous stream cipher benchmarks
#[macro_export]
macro_rules! bench_async {
    ($enc_name:ident, $dec_name:ident, $cipher:path, $data_len:expr) => {
        #[bench]
        pub fn $enc_name(bh: &mut Bencher) {
            let key = Default::default();
            let nonce = Default::default();
            let mut cipher = <$cipher>::new(&key, &nonce);
            let mut data = get_data($data_len);

            bh.iter(|| {
                cipher.encrypt(&mut data);
                test::black_box(&data);
            });
            bh.bytes = data.len() as u64;
        }

        #[bench]
        pub fn $dec_name(bh: &mut Bencher) {
            let key = Default::default();
            let nonce = Default::default();
            let mut cipher = <$cipher>::new(&key, &nonce);
            let mut data = get_data($data_len);

            bh.iter(|| {
                cipher.decrypt(&mut data);
                test::black_box(&data);
            });
            bh.bytes = data.len() as u64;
        }
    };
    ($cipher:path) => {
        extern crate test;

        use stream_cipher::generic_array::GenericArray;
        use stream_cipher::{NewStreamCipher, StreamCipher};
        use test::Bencher;

        #[inline(never)]
        fn get_data(n: usize) -> Vec<u8> {
            vec![77; n]
        }

        bench_async!(encrypt_10, decrypt_10, $cipher, 10);
        bench_async!(encrypt_100, decrypt_100, $cipher, 100);
        bench_async!(encrypt_1000, decrypt_1000, $cipher, 1000);
        bench_async!(encrypt_10000, decrypt_10000, $cipher, 10000);
        bench_async!(encrypt_100000, decrypt_100000, $cipher, 100000);
    };
}
