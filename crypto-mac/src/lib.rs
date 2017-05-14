#![no_std]
extern crate constant_time_eq;
extern crate generic_array;

use constant_time_eq::constant_time_eq;
use generic_array::{GenericArray, ArrayLength};

/// The Mac trait defines methods for a Message Authentication function.
pub trait Mac: core::marker::Sized {
    type OutputSize: ArrayLength<u8>;

    /// Create new MAC instance. DO NOT USE low-entropy keys (e.g. passwords)!
    ///
    /// For low-entropy keys first use an appropriate key derivation
    /// function (KDF), e.g. argon2, scrypt or PBKDF2
    fn new(key: &[u8]) -> Self;

    /// Process input data.
    fn input(&mut self, data: &[u8]);

    /// Obtain the result of a `Mac` computation as a `MacResult`.
    fn result(self) -> MacResult<Self::OutputSize>;

    /// Check if code is correct for the processed input
    fn verify(self, code: &[u8]) -> bool {
        MacResult::from_slice(code) == self.result()
    }
}

/// `MacResult` wraps a Mac code and provides a safe Eq implementation that runs
/// in fixed time.
pub struct MacResult<N: ArrayLength<u8>> {
    code: GenericArray<u8, N>
}

impl<N> MacResult<N> where N: ArrayLength<u8> {
    /// Create a new MacResult.
    pub fn new(code: GenericArray<u8, N>) -> MacResult<N> {
        MacResult{code: code}
    }

    pub fn from_slice(code: &[u8]) -> MacResult<N> {
        assert_eq!(code.len(), N::to_usize());
        let mut arr = GenericArray::default();
        arr.copy_from_slice(code);
        MacResult{code: arr}
    }

    /// Get the code value. Be very careful using this method, since incorrect use
    /// of the code value may permit timing attacks which defeat the security
    /// provided by the Mac function.
    pub fn code(&self) -> &[u8] {
        &self.code[..]
    }
}

impl<N> PartialEq for MacResult<N> where N: ArrayLength<u8> {
    fn eq(&self, x: &MacResult<N>) -> bool {
        constant_time_eq(&self.code[..], &x.code[..])
    }
}

impl<N> Eq for MacResult<N> where N: ArrayLength<u8> { }
