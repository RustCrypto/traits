//! Development-related functionality

pub use blobby;

use super::{ExtendableOutput, Reset, Update, VariableOutput, XofReader};
use core::fmt::Debug;

/// Define test
#[macro_export]
#[cfg_attr(docsrs, doc(cfg(feature = "dev")))]
macro_rules! new_test {
    ($name:ident, $test_name:expr, $hasher:ty, $test_func:ident $(,)?) => {
        #[test]
        fn $name() {
            use digest::dev::blobby::Blob2Iterator;
            let data = include_bytes!(concat!("data/", $test_name, ".blb"));

            for (i, row) in Blob2Iterator::new(data).unwrap().enumerate() {
                let [input, output] = row.unwrap();
                if let Some(desc) = $test_func::<$hasher>(input, output) {
                    panic!(
                        "\n\
                         Failed test №{}: {}\n\
                         input:\t{:?}\n\
                         output:\t{:?}\n",
                        i, desc, input, output,
                    );
                }
            }
        }
    };
}

/// Module to separate Digest from other traits
mod foo {
    use super::super::{Digest, Reset};
    use core::fmt::Debug;

    /// Digest test
    pub fn digest_test<D>(input: &[u8], output: &[u8]) -> Option<&'static str>
    where
        D: Digest + Reset + Debug + Clone,
    {
        let mut hasher = D::new();
        // Test that it works when accepting the message all at once
        hasher.update(input);
        let mut hasher2 = hasher.clone();
        if hasher.finalize().as_slice() != output {
            return Some("whole message");
        }

        // Test if reset works correctly
        hasher2.reset();
        hasher2.update(input);
        if hasher2.finalize().as_slice() != output {
            return Some("whole message after reset");
        }

        // Test that it works when accepting the message in pieces
        let mut hasher = D::new();
        let len = input.len();
        let mut left = len;
        while left > 0 {
            let take = (left + 1) / 2;
            hasher.update(&input[len - left..take + len - left]);
            left -= take;
        }
        if hasher.finalize().as_slice() != output {
            return Some("message in pieces");
        }

        // Test processing byte-by-byte
        let mut hasher = D::new();
        for chunk in input.chunks(1) {
            hasher.update(chunk)
        }
        if hasher.finalize().as_slice() != output {
            return Some("message byte-by-byte");
        }
        None
    }

    /// Compute digest of one million `a` bytes
    pub fn one_million_a<D>(expected: &[u8])
    where
        D: Digest + Debug + Clone,
    {
        let mut sh = D::new();
        for _ in 0..50_000 {
            sh.update(&[b'a'; 10]);
        }
        sh.update(&[b'a'; 500_000][..]);
        let out = sh.finalize();
        assert_eq!(out[..], expected[..]);
    }
}

pub use self::foo::{digest_test, one_million_a};

/// XOF test
pub fn xof_test<D>(input: &[u8], output: &[u8]) -> Option<&'static str>
where
    D: Update + ExtendableOutput + Default + Debug + Reset + Clone,
{
    let mut hasher = D::default();
    let mut buf = [0u8; 1024];
    // Test that it works when accepting the message all at once
    hasher.update(input);

    let mut hasher2 = hasher.clone();
    {
        let out = &mut buf[..output.len()];
        hasher.finalize_xof().read(out);

        if out != output {
            return Some("whole message");
        }
    }

    // Test if hasher resets correctly
    hasher2.reset();
    hasher2.update(input);

    {
        let out = &mut buf[..output.len()];
        hasher2.finalize_xof().read(out);

        if out != output {
            return Some("whole message after reset");
        }
    }

    // Test if hasher accepts message in pieces correctly
    let mut hasher = D::default();
    let len = input.len();
    let mut left = len;
    while left > 0 {
        let take = (left + 1) / 2;
        hasher.update(&input[len - left..take + len - left]);
        left -= take;
    }

    {
        let out = &mut buf[..output.len()];
        hasher.finalize_xof().read(out);
        if out != output {
            return Some("message in pieces");
        }
    }

    // Test reading from reader byte by byte
    let mut hasher = D::default();
    hasher.update(input);

    let mut reader = hasher.finalize_xof();
    let out = &mut buf[..output.len()];
    for chunk in out.chunks_mut(1) {
        reader.read(chunk);
    }

    if out != output {
        return Some("message in pieces");
    }
    None
}

/// Variable-output digest test
pub fn variable_test<D>(input: &[u8], output: &[u8]) -> Option<&'static str>
where
    D: Update + VariableOutput + Reset + Debug + Clone,
{
    let mut hasher = D::new(output.len()).unwrap();
    let mut buf = [0u8; 128];
    let buf = &mut buf[..output.len()];
    // Test that it works when accepting the message all at once
    hasher.update(input);
    let mut hasher2 = hasher.clone();
    hasher.finalize_variable(|res| buf.copy_from_slice(res));
    if buf != output {
        return Some("whole message");
    }

    // Test if reset works correctly
    hasher2.reset();
    hasher2.update(input);
    hasher2.finalize_variable(|res| buf.copy_from_slice(res));
    if buf != output {
        return Some("whole message after reset");
    }

    // Test that it works when accepting the message in pieces
    let mut hasher = D::new(output.len()).unwrap();
    let len = input.len();
    let mut left = len;
    while left > 0 {
        let take = (left + 1) / 2;
        hasher.update(&input[len - left..take + len - left]);
        left -= take;
    }
    hasher.finalize_variable(|res| buf.copy_from_slice(res));
    if buf != output {
        return Some("message in pieces");
    }

    // Test processing byte-by-byte
    let mut hasher = D::new(output.len()).unwrap();
    for chunk in input.chunks(1) {
        hasher.update(chunk)
    }
    hasher.finalize_variable(|res| buf.copy_from_slice(res));
    if buf != output {
        return Some("message byte-by-byte");
    }
    None
}

/// Define benchmark
#[macro_export]
#[cfg_attr(docsrs, doc(cfg(feature = "dev")))]
macro_rules! bench {
    ($name:ident, $engine:path, $bs:expr) => {
        #[bench]
        fn $name(b: &mut Bencher) {
            let mut d = <$engine>::default();
            let data = [0; $bs];

            b.iter(|| {
                d.update(&data[..]);
            });

            b.bytes = $bs;
        }
    };

    ($engine:path) => {
        extern crate test;

        use digest::Digest;
        use test::Bencher;

        $crate::bench!(bench1_10, $engine, 10);
        $crate::bench!(bench2_100, $engine, 100);
        $crate::bench!(bench3_1000, $engine, 1000);
        $crate::bench!(bench4_10000, $engine, 10000);
    };
}

/// Define MAC test
#[macro_export]
#[cfg(feature = "mac")]
#[cfg_attr(docsrs, doc(cfg(all(feature = "dev", feature = "mac"))))]
macro_rules! new_mac_test {
    ($name:ident, $test_name:expr, $mac:ty $(,)?) => {
        digest::new_mac_test!($name, $test_name, $mac, "");
    };
    ($name:ident, $test_name:expr, $mac:ty, trunc_left $(,)?) => {
        digest::new_mac_test!($name, $test_name, $mac, "left");
    };
    ($name:ident, $test_name:expr, $mac:ty, trunc_right $(,)?) => {
        digest::new_mac_test!($name, $test_name, $mac, "right");
    };
    ($name:ident, $test_name:expr, $mac:ty, $trunc:expr $(,)?) => {
        #[test]
        fn $name() {
            use core::cmp::min;
            use digest::dev::blobby::Blob3Iterator;
            use digest::Mac;

            fn run_test(key: &[u8], input: &[u8], tag: &[u8]) -> Option<&'static str> {
                let mac0 = <$mac as Mac>::new_from_slice(key).unwrap();

                let mut mac = mac0.clone();
                mac.update(input);
                let result = mac.finalize().into_bytes();
                let n = tag.len();
                let result_bytes = match $trunc {
                    "left" => &result[..n],
                    "right" => &result[result.len() - n..],
                    _ => &result[..],
                };
                if result_bytes != tag {
                    return Some("whole message");
                }

                // test reading different chunk sizes
                for chunk_size in 1..min(64, input.len()) {
                    let mut mac = mac0.clone();
                    for chunk in input.chunks(chunk_size) {
                        mac.update(chunk);
                    }
                    let res = match $trunc {
                        "left" => mac.verify_truncated_left(tag),
                        "right" => mac.verify_truncated_right(tag),
                        _ => mac.verify_slice(tag),
                    };
                    if res.is_err() {
                        return Some("chunked message");
                    }
                }

                None
            }

            let data = include_bytes!(concat!("data/", $test_name, ".blb"));

            for (i, row) in Blob3Iterator::new(data).unwrap().enumerate() {
                let [key, input, tag] = row.unwrap();
                if let Some(desc) = run_test(key, input, tag) {
                    panic!(
                        "\n\
                         Failed test №{}: {}\n\
                         key:\t{:?}\n\
                         input:\t{:?}\n\
                         tag:\t{:?}\n",
                        i, desc, key, input, tag,
                    );
                }
            }
        }
    };
}

/// Define new test for a resettable MAC
#[macro_export]
#[cfg(feature = "mac")]
#[cfg_attr(docsrs, doc(cfg(all(feature = "dev", feature = "mac"))))]
macro_rules! new_resettable_mac_test {
    ($name:ident, $test_name:expr, $mac:ty $(,)?) => {
        digest::new_resettable_mac_test!($name, $test_name, $mac, "");
    };
    ($name:ident, $test_name:expr, $mac:ty, trunc_left $(,)?) => {
        digest::new_resettable_mac_test!($name, $test_name, $mac, "left");
    };
    ($name:ident, $test_name:expr, $mac:ty, trunc_right $(,)?) => {
        digest::new_resettable_mac_test!($name, $test_name, $mac, "right");
    };
    ($name:ident, $test_name:expr, $mac:ty, $trunc:expr $(,)?) => {
        #[test]
        fn $name() {
            use core::cmp::min;
            use digest::dev::blobby::Blob3Iterator;
            use digest::Mac;

            fn run_test(key: &[u8], input: &[u8], tag: &[u8]) -> Option<&'static str> {
                let mac0 = <$mac as Mac>::new_from_slice(key).unwrap();

                let mut mac = mac0.clone();
                mac.update(input);
                let result = mac.finalize_reset().into_bytes();
                let n = tag.len();
                let result_bytes = match $trunc {
                    "left" => &result[..n],
                    "right" => &result[result.len() - n..],
                    _ => &result[..],
                };
                if result_bytes != tag {
                    return Some("whole message");
                }

                // test if reset worked correctly
                mac.update(input);
                let res = match $trunc {
                    "left" => mac.verify_truncated_left(tag),
                    "right" => mac.verify_truncated_right(tag),
                    _ => mac.verify_slice(tag),
                };
                if res.is_err() {
                    return Some("after reset");
                }

                // test reading different chunk sizes
                for chunk_size in 1..min(64, input.len()) {
                    let mut mac = mac0.clone();
                    for chunk in input.chunks(chunk_size) {
                        mac.update(chunk);
                    }
                    let res = match $trunc {
                        "left" => mac.verify_truncated_left(tag),
                        "right" => mac.verify_truncated_right(tag),
                        _ => mac.verify_slice(tag),
                    };
                    if res.is_err() {
                        return Some("chunked message");
                    }
                }
                None
            }

            let data = include_bytes!(concat!("data/", $test_name, ".blb"));

            for (i, row) in Blob3Iterator::new(data).unwrap().enumerate() {
                let [key, input, tag] = row.unwrap();
                if let Some(desc) = run_test(key, input, tag) {
                    panic!(
                        "\n\
                         Failed test №{}: {}\n\
                         key:\t{:?}\n\
                         input:\t{:?}\n\
                         tag:\t{:?}\n",
                        i, desc, key, input, tag,
                    );
                }
            }
        }
    };
}
