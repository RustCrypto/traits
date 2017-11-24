use super::Mac;

#[macro_export]
macro_rules! new_test {
    ($name:ident, $test_name:expr, $mac:ty) => {
        #[test]
        fn $name() {
            use crypto_mac::{Mac, MacResult};
            use crypto_mac::generic_array::GenericArray;

            fn run_test(key: &[u8], input: &[u8], tag: &[u8]) -> bool {
                let mut mac = <$mac as Mac>::new(key).unwrap();
                mac.input(&test.input[..]);
                let result = mac.result();
                let atag = GenericArray::clone_from_slice(tag);
                if result != MacResult::new(atag) {
                    return false;
                }
                // test if reset worked correctly
                mac.input(&test.input[..]);
                if mac.verify(&tag).is_err() {
                    return false;
                }

                // test reading byte by byte
                for i in 0..test.input.len() {
                    mac.input(&test.input[i..i + 1]);
                }
                mac.verify(test.output).unwrap();
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

        bench!(bench1_10,    $engine, $key_size, 10);
        bench!(bench2_100,   $engine, $key_size, 100);
        bench!(bench3_1000,  $engine, $key_size, 1000);
        bench!(bench3_10000, $engine, $key_size, 10000);
    }
}
