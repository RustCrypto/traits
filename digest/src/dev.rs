use super::{Digest, Input, VariableOutput, ExtendableOutput, XofReader};
use core::fmt::Debug;

pub struct Test {
    pub name: &'static str,
    pub input: &'static [u8],
    pub output: &'static [u8],
}

#[macro_export]
macro_rules! new_tests {
    [ $( $name:expr ),*  ] => {
        [$(
            Test {
                name: $name,
                input: include_bytes!(concat!("data/", $name, ".input.bin")),
                output: include_bytes!(concat!("data/", $name, ".output.bin")),
            },
        )*]
    };
    [ $( $name:expr ),+, ] => (new_tests![$($name),+])
}

pub fn run_digest_tests<D: Digest + Debug + Clone>(tests: &[Test]) {
    // Test that it works when accepting the message all at once
    for t in tests.iter() {
        let mut sh = D::default();
        sh.input(t.input);

        let out = sh.result();

        assert_eq!(out[..], t.output[..]);
    }

    // Test that it works when accepting the message in pieces
    for t in tests.iter() {
        let mut sh = D::default();
        let len = t.input.len();
        let mut left = len;
        while left > 0 {
            let take = (left + 1) / 2;
            sh.input(&t.input[len - left..take + len - left]);
            left = left - take;
        }

        let out = sh.result();

        assert_eq!(out[..], t.output[..]);
    }
}

pub fn run_variable_tests<D>(tests: &[Test])
    where D: Input + VariableOutput + Clone + Debug
{
    let mut buf = [0u8; 1024];
    // Test that it works when accepting the message all at once
    for t in tests.iter() {
        let mut sh = D::new(t.output.len()).unwrap();
        sh.process(t.input);

        let out = sh.variable_result(&mut buf[..t.output.len()]).unwrap();

        assert_eq!(out[..], t.output[..]);
    }

    // Test that it works when accepting the message in pieces
    for t in tests.iter() {
        let mut sh = D::new(t.output.len()).unwrap();
        let len = t.input.len();
        let mut left = len;
        while left > 0 {
            let take = (left + 1) / 2;
            sh.process(&t.input[len - left..take + len - left]);
            left = left - take;
        }

        let out = sh.variable_result(&mut buf[..t.output.len()]).unwrap();

        assert_eq!(out[..], t.output[..]);
    }
}


pub fn run_xof_tests<D>(tests: &[Test])
    where D: Input + ExtendableOutput + Default + Debug + Clone
{
    let mut buf = [0u8; 1024];
    // Test that it works when accepting the message all at once
    for t in tests.iter() {
        let mut sh = D::default();
        sh.process(t.input);

        let out = &mut buf[..t.output.len()];
        sh.xof_result().read(out);

        assert_eq!(out[..], t.output[..]);
    }

    // Test that it works when accepting the message in pieces
    for t in tests.iter() {
        let mut sh = D::default();
        let len = t.input.len();
        let mut left = len;
        while left > 0 {
            let take = (left + 1) / 2;
            sh.process(&t.input[len - left..take + len - left]);
            left = left - take;
        }

        let out = &mut buf[..t.output.len()];
        sh.xof_result().read(out);

        assert_eq!(out[..], t.output[..]);
    }

    // Test reeading from reader byte by byte
    for t in tests.iter() {
        let mut sh = D::default();
        sh.process(t.input);

        let mut reader = sh.xof_result();
        let out = &mut buf[..t.output.len()];
        for chunk in out.chunks_mut(1) {
            reader.read(chunk);
        }

        assert_eq!(out[..], t.output[..]);
    }
}

pub fn run_1mil_a_test<D: Digest + Default + Debug + Clone>(expected: &[u8]) {
    let mut sh = D::default();
    for _ in 0..50_000 {
        sh.input(&[b'a'; 10]);
    }
    sh.input(&[b'a'; 500_000]);
    let out = sh.result();
    assert_eq!(out[..], expected[..]);
}


#[macro_export]
macro_rules! bench {
    ($name:ident, $engine:path, $bs:expr) => {
        #[bench]
        fn $name(b: &mut Bencher) {
            let mut d = <$engine>::default();
            let data = [0; $bs];

            b.iter(|| {
                d.input(&data);
            });

            b.bytes = $bs;
        }
    };

    ($engine:path) => {
        extern crate test;

        use test::Bencher;
        use digest::Digest;

        bench_digest!(bench1_10,    $engine, 10);
        bench_digest!(bench2_100,   $engine, 100);
        bench_digest!(bench3_1000,  $engine, 1000);
        bench_digest!(bench4_10000, $engine, 10000);
    }
}
