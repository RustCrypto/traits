//! Tests for `PasswordHash` encoding/decoding.
//!
//! Each test implements a different permutation of the possible combinations
//! of the string encoding, and ensures password hashes round trip under each
//! of the conditions.

#![cfg(feature = "registry")]

use core::convert::TryInto;
use password_hash::{algorithm::argon2, Algorithm, Params, PasswordHash};

const EXAMPLE_ALGORITHM: Algorithm = Algorithm::Argon2(argon2::Variant::D);
const EXAMPLE_SALT: &[u8] = &[
    0xb1, 0xa9, 0x6d, 0xb1, 0xa9, 0x6d, 0xb1, 0xa9, 0x6d, 0xb1, 0xa9, 0x6d, 0xb1, 0xa9, 0x6d, 0xb0,
];
const EXAMPLE_HASH: &[u8] = &[
    0x85, 0xab, 0x21, 0x85, 0xab, 0x21, 0x85, 0xab, 0x21, 0x85, 0xab, 0x21, 0x85, 0xab, 0x21, 0x85,
    0xab, 0x21, 0x85, 0xab, 0x21, 0x85, 0xab, 0x21, 0x85, 0xab, 0x21, 0x85, 0xab, 0x21, 0x85, 0xab,
];

/// Example parameters
fn example_params() -> Params {
    Params::from_slice(&[
        ("a".parse().unwrap(), 1u32.into()),
        ("b".parse().unwrap(), 2u32.into()),
        ("c".parse().unwrap(), 3u32.into()),
    ])
    .unwrap()
}

#[test]
fn algorithm_alone() {
    let ph = PasswordHash::from(EXAMPLE_ALGORITHM);

    let s = ph.to_string();
    assert_eq!(s, "$argon2d");

    let ph2 = s.parse::<PasswordHash>().unwrap();
    assert_eq!(ph, ph2);
}

#[test]
fn params() {
    let ph = PasswordHash {
        algorithm: EXAMPLE_ALGORITHM,
        params: example_params(),
        salt: None,
        hash: None,
    };

    let s = ph.to_string();
    assert_eq!(s, "$argon2d$a=1,b=2,c=3");

    let ph2 = s.parse::<PasswordHash>().unwrap();
    assert_eq!(ph, ph2);
}

#[test]
fn salt() {
    let ph = PasswordHash {
        algorithm: EXAMPLE_ALGORITHM,
        params: Params::new(),
        salt: Some(EXAMPLE_SALT.try_into().unwrap()),
        hash: None,
    };

    let s = ph.to_string();
    assert_eq!(s, "$argon2d$saltsaltsaltsaltsaltsA");

    let ph2 = s.parse::<PasswordHash>().unwrap();
    assert_eq!(ph, ph2);
}

#[test]
fn one_param_and_salt() {
    let params = Params::from_slice(&[("a".parse().unwrap(), 1u32.into())]).unwrap();

    let ph = PasswordHash {
        algorithm: EXAMPLE_ALGORITHM,
        params,
        salt: Some(EXAMPLE_SALT.try_into().unwrap()),
        hash: None,
    };

    let s = ph.to_string();
    assert_eq!(s, "$argon2d$a=1$saltsaltsaltsaltsaltsA");

    let ph2 = s.parse::<PasswordHash>().unwrap();
    assert_eq!(ph, ph2);
}

#[test]
fn params_and_salt() {
    let ph = PasswordHash {
        algorithm: EXAMPLE_ALGORITHM,
        params: example_params(),
        salt: Some(EXAMPLE_SALT.try_into().unwrap()),
        hash: None,
    };

    let s = ph.to_string();
    assert_eq!(s, "$argon2d$a=1,b=2,c=3$saltsaltsaltsaltsaltsA");

    let ph2 = s.parse::<PasswordHash>().unwrap();
    assert_eq!(ph, ph2);
}

#[test]
fn salt_and_hash() {
    let ph = PasswordHash {
        algorithm: EXAMPLE_ALGORITHM,
        params: Params::default(),
        salt: Some(EXAMPLE_SALT.try_into().unwrap()),
        hash: Some(EXAMPLE_HASH.try_into().unwrap()),
    };

    let s = ph.to_string();
    assert_eq!(
        s,
        "$argon2d$saltsaltsaltsaltsaltsA$hashhashhashhashhashhashhashhashhashhashhas"
    );

    let ph2 = s.parse::<PasswordHash>().unwrap();
    assert_eq!(ph, ph2);
}

#[test]
fn all_fields() {
    let ph = PasswordHash {
        algorithm: EXAMPLE_ALGORITHM,
        params: example_params(),
        salt: Some(EXAMPLE_SALT.try_into().unwrap()),
        hash: Some(EXAMPLE_HASH.try_into().unwrap()),
    };

    let s = ph.to_string();
    assert_eq!(
        s,
        "$argon2d$a=1,b=2,c=3$saltsaltsaltsaltsaltsA$hashhashhashhashhashhashhashhashhashhashhas"
    );

    let ph2 = s.parse::<PasswordHash>().unwrap();
    assert_eq!(ph, ph2);
}
