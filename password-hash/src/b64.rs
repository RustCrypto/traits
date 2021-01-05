//! "B64" encoding.
//!
//! Subset of the standard Base64 encoding (RFC 4648, section 4) which omits
//! padding (`=`) as well as extra whitespace, as described in the PHC string
//! format specification:
//!
//! <https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#b64>
//!
//! Supports the Base64 character subset: `[A-Z]`, `[a-z]`, `[0-9]`, `+`, `/`
//!
//! Adapted from the following constant-time C++ implementation of Base64:
//!
//! <https://github.com/Sc00bz/ConstTimeEncoding/blob/master/base64.cpp>
//!
//! Copyright (c) 2014 Steve "Sc00bz" Thomas (steve at tobtu dot com).
//! Derived code is dual licensed MIT + Apache 2 (with permission from Sc00bz).

use crate::errors::B64Error;
use core::str;

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

/// Error message to use when performing encoding operations which we expect
/// will never fail, i.e. the message passed to `expect()`.
const ENCODING_ERROR: &str = "B64 encoding error";

/// Encode the input byte slice as "B64", writing the result into the provided
/// destination slice, and returning an ASCII-encoded string value.
pub fn encode<'a>(src: &[u8], dst: &'a mut [u8]) -> Result<&'a str, B64Error> {
    if encoded_len(src) > dst.len() {
        return Err(B64Error::LengthInvalid);
    }

    let mut src_offset: usize = 0;
    let mut dst_offset: usize = 0;
    let mut src_length: usize = src.len();

    while src_length >= 3 {
        encode_3bytes(
            &src[src_offset..(src_offset + 3)],
            &mut dst[dst_offset..(dst_offset + 4)],
        );

        src_offset += 3;
        dst_offset += 4;
        src_length -= 3;
    }

    if src_length > 0 {
        let remaining = &src[src_offset..(src_offset + src_length)];
        let mut tmp_in = [0u8; 3];
        tmp_in[..src_length].copy_from_slice(remaining);

        let mut tmp_out = [0u8; 4];
        encode_3bytes(&tmp_in, &mut tmp_out);

        let len = encoded_len(remaining);
        dst[dst_offset..(dst_offset + len)].copy_from_slice(&tmp_out[..len]);
        dst_offset += len;
    }

    Ok(str::from_utf8(&dst[..dst_offset]).expect(ENCODING_ERROR))
}

/// Encode the input byte slice as a "B64"-encoded [`String`].
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub fn encode_string(input: &[u8]) -> String {
    let expected_len = encoded_len(input);
    let mut output = vec![0u8; expected_len];
    let actual_len = encode(input, &mut output).expect(ENCODING_ERROR).len();
    debug_assert_eq!(expected_len, actual_len);
    String::from_utf8(output).expect(ENCODING_ERROR)
}

/// Get the "B64"-encoded length of the given byte slice.
pub const fn encoded_len(bytes: &[u8]) -> usize {
    let q = bytes.len() * 4;
    let r = q % 3;
    (q / 3) + (r != 0) as usize
}

/// "B64" decode the given source byte slice into the provided destination
/// buffer.
pub fn decode<'a>(src: &str, dst: &'a mut [u8]) -> Result<&'a [u8], B64Error> {
    if decoded_len(src) > dst.len() {
        return Err(B64Error::LengthInvalid);
    }

    let src = src.as_bytes();

    if !src.is_empty() && char::from(src[src.len() - 1]).is_whitespace() {
        return Err(B64Error::TrailingWhitespace);
    }

    let mut src_offset: usize = 0;
    let mut dst_offset: usize = 0;
    let mut src_length: usize = src.len();
    let mut err: isize = 0;

    while src_length > 4 {
        err |= decode_3bytes(
            &src[src_offset..(src_offset + 4)],
            &mut dst[dst_offset..(dst_offset + 3)],
        );
        src_offset += 4;
        dst_offset += 3;
        src_length -= 4;
    }

    if src_length > 0 {
        let mut i = 0;
        let mut tmp_out = [0u8; 3];
        let mut tmp_in = [b'A'; 4];

        while i < src_length {
            tmp_in[i] = src[src_offset + i];
            i += 1;
        }

        if i < 2 {
            err = 1;
        }

        src_length = i - 1;
        err |= decode_3bytes(&tmp_in, &mut tmp_out);
        dst[dst_offset..(dst_offset + src_length)].copy_from_slice(&tmp_out[..src_length]);
        dst_offset += i - 1;
    }

    if err == 0 {
        Ok(&dst[..dst_offset])
    } else {
        Err(B64Error::EncodingInvalid)
    }
}

/// Decode a "B64"-encoded string into a byte vector.
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub fn decode_vec(input: &str) -> Result<Vec<u8>, B64Error> {
    let expected_len = decoded_len(input);
    let mut output = vec![0u8; expected_len];
    let actual_len = decode(input, &mut output)?.len();
    debug_assert_eq!(expected_len, actual_len);
    Ok(output)
}

/// Get the length of the output from decoding the provided "B64"-encoded input.
pub const fn decoded_len(bytes: &str) -> usize {
    (bytes.len() * 3) / 4
}

// B64 character set:
// [A-Z]      [a-z]      [0-9]      +     /
// 0x41-0x5a, 0x61-0x7a, 0x30-0x39, 0x2b, 0x2f

#[inline]
fn encode_3bytes(src: &[u8], dst: &mut [u8]) {
    debug_assert_eq!(src.len(), 3);
    debug_assert!(dst.len() >= 4, "dst too short: {}", dst.len());

    let b0 = src[0] as isize;
    let b1 = src[1] as isize;
    let b2 = src[2] as isize;

    dst[0] = encode_6bits(b0 >> 2);
    dst[1] = encode_6bits(((b0 << 4) | (b1 >> 4)) & 63);
    dst[2] = encode_6bits(((b1 << 2) | (b2 >> 6)) & 63);
    dst[3] = encode_6bits(b2 & 63);
}

#[inline]
fn encode_6bits(src: isize) -> u8 {
    let mut diff = 0x41isize;

    // if (in > 25) diff += 0x61 - 0x41 - 26; // 6
    diff += ((25isize - src) >> 8) & 6;

    // if (in > 51) diff += 0x30 - 0x61 - 26; // -75
    diff -= ((51isize - src) >> 8) & 75;

    // if (in > 61) diff += 0x2b - 0x30 - 10; // -15
    diff -= ((61isize - src) >> 8) & 15;

    // if (in > 62) diff += 0x2f - 0x2b - 1; // 3
    diff += ((62isize - src) >> 8) & 3;

    (src + diff) as u8
}

#[inline]
fn decode_3bytes(src: &[u8], dst: &mut [u8]) -> isize {
    debug_assert_eq!(src.len(), 4);
    debug_assert!(dst.len() >= 3, "dst too short: {}", dst.len());

    let c0 = decode_6bits(src[0]);
    let c1 = decode_6bits(src[1]);
    let c2 = decode_6bits(src[2]);
    let c3 = decode_6bits(src[3]);

    dst[0] = ((c0 << 2) | (c1 >> 4)) as u8;
    dst[1] = ((c1 << 4) | (c2 >> 2)) as u8;
    dst[2] = ((c2 << 6) | c3) as u8;

    ((c0 | c1 | c2 | c3) >> 8) & 1
}

#[inline]
fn decode_6bits(src: u8) -> isize {
    let ch = src as isize;
    let mut ret: isize = -1;

    // if (ch > 0x40 && ch < 0x5b) ret += ch - 0x41 + 1; // -64
    ret += (((64isize - ch) & (ch - 91isize)) >> 8) & (ch - 64isize);

    // if (ch > 0x60 && ch < 0x7b) ret += ch - 0x61 + 26 + 1; // -70
    ret += (((96isize - ch) & (ch - 123isize)) >> 8) & (ch - 70isize);

    // if (ch > 0x2f && ch < 0x3a) ret += ch - 0x30 + 52 + 1; // 5
    ret += (((47isize - ch) & (ch - 58isize)) >> 8) & (ch + 5isize);

    // if (ch == 0x2b) ret += 62 + 1;
    ret += (((42isize - ch) & (ch - 44isize)) >> 8) & 63;

    // if (ch == 0x2f) ret += 63 + 1;
    ret + ((((46isize - ch) & (ch - 48isize)) >> 8) & 64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// "B64" test vector
    struct TestVector {
        /// Raw bytes.
        raw: &'static [u8],

        /// "B64" encoded.
        b64: &'static str,
    }

    const TEST_VECTORS: &[TestVector] = &[
        TestVector { raw: b"", b64: "" },
        TestVector {
            raw: b"\0",
            b64: "AA",
        },
        TestVector {
            raw: b"***",
            b64: "Kioq",
        },
        TestVector {
            raw: b"\x01\x02\x03\x04",
            b64: "AQIDBA",
        },
        TestVector {
            raw: b"\xAD\xAD\xAD\xAD\xAD",
            b64: "ra2tra0",
        },
        TestVector {
            raw: b"\xFF\xFF\xFF\xFF\xFF",
            b64: "//////8",
        },
        TestVector {
            raw: b"\x40\xC1\x3F\xBD\x05\x4C\x72\x2A\xA3\xC2\xF2\x11\x73\xC0\x69\xEA\
                   \x49\x7D\x35\x29\x6B\xCC\x24\x65\xF6\xF9\xD0\x41\x08\x7B\xD7\xA9",
            b64: "QME/vQVMciqjwvIRc8Bp6kl9NSlrzCRl9vnQQQh716k",
        },
    ];

    #[test]
    fn encode_test_vectors() {
        let mut buf = [0u8; 1024];

        for vector in TEST_VECTORS {
            let out = encode(vector.raw, &mut buf).unwrap();
            assert_eq!(encoded_len(vector.raw), vector.b64.len());
            assert_eq!(vector.b64, &out[..]);
        }
    }

    #[test]
    fn decode_test_vectors() {
        let mut buf = [0u8; 1024];

        for vector in TEST_VECTORS {
            let out = decode(vector.b64, &mut buf).unwrap();
            assert_eq!(decoded_len(vector.b64), out.len());
            assert_eq!(vector.raw, &out[..]);
        }
    }

    #[test]
    fn encode_and_decode_various_lengths() {
        let data = [b'X'; 64];
        let mut inbuf = [0u8; 1024];
        let mut outbuf = [0u8; 1024];

        for i in 0..data.len() {
            let encoded = encode(&data[..i], &mut inbuf).unwrap();

            // Make sure it round trips
            let decoded = decode(encoded, &mut outbuf).unwrap();
            assert_eq!(decoded, &data[..i]);
        }
    }

    #[test]
    fn reject_trailing_equals() {
        let input = "QME/vQVMciqjwvIRc8Bp6kl9NSlrzCRl9vnQQQh716k=";
        let mut buf = [0u8; 1024];
        assert_eq!(decode(input, &mut buf), Err(B64Error::EncodingInvalid));
    }

    #[test]
    fn reject_trailing_whitespace() {
        let input = "QME/vQVMciqjwvIRc8Bp6kl9NSlrzCRl9vnQQQh716k\n";
        let mut buf = [0u8; 1024];
        assert_eq!(decode(input, &mut buf), Err(B64Error::TrailingWhitespace));
    }
}
