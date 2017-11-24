
#[macro_export]
macro_rules! new_test {
    ($name:ident, $test_name:expr, $mac:ty) => {
        #[test]
        fn $name() {
            use crypto_mac::Mac;

            fn run_test(key: &[u8], input: &[u8], tag: &[u8]) -> bool {
                let mut mac = <$mac as Mac>::new_varkey(key).unwrap();
                mac.input(input);
                let result = mac.result();
                if !result.is_equal(tag) {
                    return false;
                }
                // test if reset worked correctly
                mac.input(input);
                if mac.verify(&tag).is_err() {
                    return false;
                }

                // test reading byte by byte
                for i in 0..input.len() {
                    mac.input(&input[i..i + 1]);
                }
                mac.verify(tag).unwrap();
                true
            }

            let keys = include_bytes!(
                concat!("data/", $test_name, ".keys.bin"));
            let inputs = include_bytes!(
                concat!("data/", $test_name, ".inputs.bin"));
            let tags = include_bytes!(
                concat!("data/", $test_name, ".tags.bin"));
            let index = include_bytes!(
                concat!("data/", $test_name, ".index.bin"));

            // u32 (2 bytes); start + end (x2); key, input, tag (x3)
            assert_eq!(index.len() % (2*3*2), 0, "invlaid index length");
            for (i, chunk) in index.chunks(2*3*2).enumerate() {
                // proper aligment is assumed here
                let mut idx = unsafe {
                    *(chunk.as_ptr() as *const [[u16; 2]; 3])
                };
                // convert to LE for BE machine
                for val in idx.iter_mut() {
                    for i in val.iter_mut() { *i = i.to_le(); }
                }
                let key = &keys[(idx[0][0] as usize)..(idx[0][1] as usize)];
                let input = &inputs[
                    (idx[1][0] as usize)..(idx[1][1] as usize)];
                let tag = &tags[
                    (idx[2][0] as usize)..(idx[2][1] as usize)];
                if !run_test(key, input, tag) {
                    panic!("\n\
                        Failed test №{}\n\
                        key: [{}..{}]\t{:?}\n\
                        input: [{}..{}]\t{:?}\n\
                        tag: [{}..{}]\t{:?}\n",
                        i, idx[0][0], idx[0][1], key,
                        idx[1][0], idx[1][1], input,
                        idx[2][0], idx[2][1], tag,
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
