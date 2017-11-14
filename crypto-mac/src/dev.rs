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

pub fn mac_test<M: Mac>(tests: &[MacTest]) {
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
