//! Development-related functionality
pub use blobby;

#[cfg(all(feature = "alloc", feature = "inout"))]
use {
    crate::Tag, alloc::vec, alloc::vec::Vec, core::fmt, crypto_common::typenum::Unsigned,
    inout::InOutBuf,
};

/// Define AEAD test
#[macro_export]
macro_rules! new_test {
    ($name:ident, $test_name:expr, $cipher:ty $(,)?) => {
        #[test]
        fn $name() {
            use aead::{
                Aead, KeyInit, Payload,
                array::{Array, typenum::Unsigned},
                dev::blobby::Blob6Iterator,
            };

            fn run_test(
                key: &[u8],
                nonce: &[u8],
                aad: &[u8],
                pt: &[u8],
                ct: &[u8],
                pass: bool,
            ) -> Result<(), &'static str> {
                let key = key.try_into().map_err(|_| "wrong key size")?;
                let cipher = <$cipher>::new(key);
                let nonce = nonce.try_into().map_err(|_| "wrong nonce size")?;

                if !pass {
                    let res = cipher.decrypt(nonce, Payload { aad: aad, msg: ct });
                    if res.is_ok() {
                        return Err("decryption must return error");
                    }
                    return Ok(());
                }

                let res = cipher
                    .encrypt(nonce, Payload { aad: aad, msg: pt })
                    .map_err(|_| "encryption failure")?;
                if res != ct {
                    return Err("encrypted data is different from target ciphertext");
                }
                let res = cipher
                    .decrypt(nonce, Payload { aad: aad, msg: ct })
                    .map_err(|_| "decryption failure")?;
                if res != pt {
                    return Err("decrypted data is different from target plaintext");
                }

                $crate::dev::new_test_impl_inout(cipher, nonce, aad, pt, ct, pass)?;
                Ok(())
            }

            let data = include_bytes!(concat!("data/", $test_name, ".blb"));
            for (i, row) in Blob6Iterator::new(data).unwrap().enumerate() {
                let [key, nonce, aad, pt, ct, status] = row.unwrap();
                let pass = match status[0] {
                    0 => false,
                    1 => true,
                    _ => panic!("invalid value for pass flag"),
                };
                if let Err(reason) = run_test(key, nonce, aad, pt, ct, pass) {
                    panic!(
                        "\n\
                            Failed test №{}\n\
                            reason: \t{:?}\n\
                            key:\t{:?}\n\
                            nonce:\t{:?}\n\
                            aad:\t{:?}\n\
                            plaintext:\t{:?}\n\
                            ciphertext:\t{:?}\n\
                            pass:\t{}\n\
                        ",
                        i, reason, key, nonce, aad, pt, ct, pass,
                    );
                }
            }
        }
    };
}

/// Helper to run tests against the inout API.
#[cfg(not(all(feature = "alloc", feature = "inout")))]
pub fn new_test_impl_inout<T: crate::AeadCore>(
    _cipher: T,
    _nonce: &crate::Nonce<T>,
    _aad: &[u8],
    _pt: &[u8],
    _ct: &[u8],
    _pass: bool,
) -> Result<(), &'static str> {
    Ok(())
}

/// Helper to run tests against the inout API.
#[cfg(all(feature = "alloc", feature = "inout"))]
pub fn new_test_impl_inout<T: crate::AeadInOut>(
    cipher: T,
    nonce: &crate::Nonce<T>,
    aad: &[u8],
    pt: &[u8],
    ct: &[u8],
    pass: bool,
) -> Result<(), &'static str> {
    // Here we assume this is a postfix tagged AEAD
    let (ciphertext, expected_tag) = ct.split_at(ct.len() - T::TagSize::to_usize());
    let expected_tag = Tag::<T>::try_from(expected_tag).expect("invariant violation");

    if !pass {
        let mut payload = MockBuffer::from(ciphertext);
        let res = cipher.decrypt_inout_detached(nonce, aad, payload.to_in_out_buf(), &expected_tag);
        if res.is_ok() {
            return Err("Decryption must return an error");
        }
        return Ok(());
    }

    let mut payload = MockBuffer::from(pt);
    let tag = cipher
        .encrypt_inout_detached(nonce, aad, payload.to_in_out_buf())
        .map_err(|_| "encryption failure")?;

    // Here we assume this is a postfix tagged AEAD
    let (ciphertext, _tag) = ct.split_at(ct.len() - T::TagSize::to_usize());
    if payload.as_ref() != ciphertext {
        return Err("encrypted data is different from target ciphertext");
    }

    let mut payload = MockBuffer::from(ciphertext);
    cipher
        .decrypt_inout_detached(nonce, aad, payload.to_in_out_buf(), &tag)
        .map_err(|_| "decryption failure")?;

    if payload.as_ref() != pt {
        return Err("decrypted data is different from target plaintext");
    }

    Ok(())
}

/// [`MockBuffer`] is meant for testing InOut-backed APIs.
///
/// It will split the initial buffer in two different backing buffers. The out buffer will be
/// zeroed.
#[cfg(all(feature = "alloc", feature = "inout"))]
pub struct MockBuffer {
    in_buf: Vec<u8>,
    out_buf: Vec<u8>,
}

#[cfg(all(feature = "alloc", feature = "inout"))]
impl AsRef<[u8]> for MockBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.out_buf
    }
}

#[cfg(all(feature = "alloc", feature = "inout"))]
impl From<&[u8]> for MockBuffer {
    fn from(buf: &[u8]) -> Self {
        Self {
            in_buf: buf.to_vec(),
            out_buf: vec![0u8; buf.len()],
        }
    }
}

#[cfg(all(feature = "alloc", feature = "inout"))]
impl From<Vec<u8>> for MockBuffer {
    fn from(buf: Vec<u8>) -> Self {
        Self {
            out_buf: vec![0u8; buf.len()],
            in_buf: buf,
        }
    }
}

#[cfg(all(feature = "alloc", feature = "inout"))]
impl MockBuffer {
    /// Get an [`InOutBuf`] from a [`MockBuffer`]
    pub fn to_in_out_buf(&mut self) -> InOutBuf<'_, '_, u8> {
        InOutBuf::new(self.in_buf.as_slice(), self.out_buf.as_mut_slice())
            .expect("Invariant violation")
    }

    /// Return the length of the payload
    #[inline]
    pub fn len(&self) -> usize {
        self.in_buf.len()
    }

    /// Is the payload empty?
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.in_buf.is_empty()
    }
}

#[cfg(all(feature = "alloc", feature = "inout"))]
impl fmt::Debug for MockBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MockBuffer {{...}}")
    }
}
