use super::Mac;

pub struct Test {
    pub name: &'static str,
    pub key: &'static [u8],
    pub input: &'static [u8],
    pub output: &'static [u8],
}

#[macro_export]
macro_rules! new_mac_tests {
    ( $( $name:expr ),*  ) => {
        [$(
            Test {
                name: $name,
                key: include_bytes!(concat!("data/", $name, ".key.bin")),
                input: include_bytes!(concat!("data/", $name, ".input.bin")),
                output: include_bytes!(concat!("data/", $name, ".output.bin")),
            },
        )*]
    };
}

pub fn mac_test<M: Mac>(tests: &[Test]) {
    for test in tests.iter() {
        let mut mac = M::new(test.key).unwrap();
        mac.input(&test.input[..]);
        mac.verify(test.output).unwrap();
    }

    // incremental test
    for test in tests.iter() {
        let mut mac = M::new(test.key).unwrap();
        for i in 0..test.input.len() {
            mac.input(&test.input[i..i + 1]);
        }
        mac.verify(test.output).unwrap();
    }
}

#[macro_export]
macro_rules! bench {
    ($name:ident, $engine:path, $key_size:expr, $bs:expr) => {
        #[bench]
        fn $name(b: &mut Bencher) {
            let mut m = <$engine>::new(&[0; $key_size]).unwrap();
            let data = [0; $bs];

            b.iter(|| {
                m.input(&data);
            });

            b.bytes = $bs;
        }
    };

    ($engine:path, $key_size:expr) => {
        extern crate test;

        use test::Bencher;
        use crypto_mac::Mac;

        bench!(bench3_100, $engine, $key_size, 100);
        bench!(bench4_1000, $engine, $key_size, 1000);
        bench!(bench5_10000, $engine, $key_size, 10000);
    }
}
