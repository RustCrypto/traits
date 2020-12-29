//! "B64" encoding tests.
//!
//! Subset of the standard Base64 encoding (RFC 4648, section 4) which omits
//! padding (`=`) as well as extra whitespace, as described in the PHC string
//! format specification:
//!
//! <https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#b64>

use password_hash::{Output, Salt};

#[cfg(feature = "alloc")]
use password_hash::b64;

// Example salt encoded as a B64 string.
const EXAMPLE_SALT_B64: &str = "REVBREJFRUZERUFEQkVFRg";
const EXAMPLE_SALT_RAW: &[u8] = b"DEADBEEFDEADBEEF";

// Example PHF output encoded as a B64 string.
const EXAMPLE_OUTPUT_B64: &str =
    "REVBREJFRUZERUFEQkVFRkRFQURCRUVGREVBREJFRUZERUFEQkVFRkRFQURCRUVGREVBREJFRUZERUFEQkVFRg";
const EXAMPLE_OUTPUT_RAW: &[u8] =
    b"DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF";

#[test]
fn salt_roundtrip() {
    let salt = EXAMPLE_SALT_B64.parse::<Salt>().unwrap();
    assert_eq!(salt.as_ref(), EXAMPLE_SALT_RAW);
    assert_eq!(salt.to_string(), EXAMPLE_SALT_B64);
}

#[test]
fn output_roundtrip() {
    let out = EXAMPLE_OUTPUT_B64.parse::<Output>().unwrap();
    assert_eq!(out.as_ref(), EXAMPLE_OUTPUT_RAW);
    assert_eq!(out.to_string(), EXAMPLE_OUTPUT_B64);
}

#[cfg(feature = "alloc")]
#[test]
fn encode_string() {
    assert_eq!(b64::encode_string(EXAMPLE_OUTPUT_RAW), EXAMPLE_OUTPUT_B64);
}

#[cfg(feature = "alloc")]
#[test]
fn decode_vec() {
    assert_eq!(
        b64::decode_vec(EXAMPLE_OUTPUT_B64).unwrap(),
        EXAMPLE_OUTPUT_RAW
    );
}
