
#[macro_export]
macro_rules! new_test {
    ($name:ident, $test_name:expr, $mac:ty) => {
        #[test]
        fn $name() {
            use crypto_mac::Mac;
            use crypto_mac::blobby::Blob3Iterator;

            fn run_test(key: &[u8], input: &[u8], tag: &[u8])
                -> Option<&'static str>
            {
                let mut mac = <$mac as Mac>::new_varkey(key).unwrap();
                mac.input(input);
                let result = mac.result_reset();
                if &result.code()[..] != tag {
                    return Some("whole message");
                }
                // test if reset worked correctly
                mac.input(input);
                if mac.verify(&tag).is_err() {
                    return Some("after reset");
                }

                let mut mac = <$mac as Mac>::new_varkey(key).unwrap();
                // test reading byte by byte
                for i in 0..input.len() {
                    mac.input(&input[i..i + 1]);
                }
                if let Err(_) = mac.verify(tag) {
                    return Some("message byte-by-byte");
                }
                None
            }

            let data = include_bytes!(concat!("data/", $test_name, ".blb"));

            for (i, row) in Blob3Iterator::new(data).unwrap().enumerate() {
                let key = row[0];
                let input = row[1];
                let tag = row[2];
                if let Some(desc) = run_test(key, input, tag) {
                    panic!("\n\
                        Failed test №{}: {}\n\
                        key:\t{:?}\n\
                        input:\t{:?}\n\
                        tag:\t{:?}\n",
                        i, desc, key, input, tag,
                    );
                }
            }
        }
    }
}

#[macro_export]
macro_rules! bench {
    ($name:ident, $engine:path, $bs:expr) => {
        #[bench]
        fn $name(b: &mut Bencher) {
            let key = Default::default();
            let mut m = <$engine>::new(&key);
            let data = [0; $bs];

            b.iter(|| {
                m.input(&data);
            });

            b.bytes = $bs;
        }
    };

    ($engine:path) => {
        extern crate test;

        use test::Bencher;
        use crypto_mac::Mac;

        bench!(bench1_10,    $engine, 10);
        bench!(bench2_100,   $engine, 100);
        bench!(bench3_1000,  $engine, 1000);
        bench!(bench3_10000, $engine, 10000);
    }
}
