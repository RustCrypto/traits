//! Secret key tests

#![cfg(feature = "dev")]

use elliptic_curve::{
    Curve, SecretKey,
    array::typenum::U32,
    bigint::{ByteOrder, Odd, U256},
    dev::SecretKey as MockSecretKey,
};

#[derive(Copy, Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
struct LittleEndianMockCurve;

impl Curve for LittleEndianMockCurve {
    type FieldBytesSize = U32;
    type Uint = U256;

    const ORDER: Odd<U256> = Odd::<U256>::from_be_hex(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    const FIELD_ENDIANNESS: ByteOrder = ByteOrder::LittleEndian;
}

#[test]
fn from_empty_slice() {
    assert!(MockSecretKey::from_slice(&[]).is_err());
}

#[test]
fn from_slice_expected_size() {
    let bytes = [1u8; 32];
    assert!(MockSecretKey::from_slice(&bytes).is_ok());
}

#[test]
fn from_slice_allowed_short() {
    let bytes = [1u8; 24];
    assert!(MockSecretKey::from_slice(&bytes).is_ok());
}

#[test]
fn from_slice_allowed_short_little_endian() {
    let mut bytes = [0u8; 24];
    bytes[0] = 1;

    let secret_key = SecretKey::<LittleEndianMockCurve>::from_slice(&bytes).unwrap();
    let encoded = secret_key.to_bytes();

    assert_eq!(&encoded[..bytes.len()], &bytes);
    assert_eq!(&encoded[bytes.len()..], &[0u8; 8]);
}

#[test]
fn from_slice_too_short() {
    let bytes = [1u8; 23]; // min 24-bytes
    assert!(MockSecretKey::from_slice(&bytes).is_err());
}
