//! Traits which define functionality of stream ciphers.
//!
//! See the [RustCrypto/stream-ciphers](https://github.com/RustCrypto/stream-ciphers) repository
//! for ciphers implementation.

use crate::block::{BlockModeDecrypt, BlockModeEncrypt};
use common::Block;
use inout::{InOutBuf, NotEqualError};

mod core_api;
mod errors;
#[cfg(feature = "stream-wrapper")]
mod wrapper;

pub use core_api::{
    StreamCipherBackend, StreamCipherClosure, StreamCipherCore, StreamCipherCounter,
    StreamCipherSeekCore,
};
pub use errors::{OverflowError, StreamCipherError};
#[cfg(feature = "stream-wrapper")]
pub use wrapper::StreamCipherCoreWrapper;

/// Asynchronous stream cipher trait.
pub trait AsyncStreamCipher: Sized {
    /// Encrypt data using `InOutBuf`.
    fn encrypt_inout(mut self, data: InOutBuf<'_, '_, u8>)
    where
        Self: BlockModeEncrypt,
    {
        let (blocks, mut tail) = data.into_chunks();
        self.encrypt_blocks_inout(blocks);
        let n = tail.len();
        if n != 0 {
            let mut block = Block::<Self>::default();
            block[..n].copy_from_slice(tail.get_in());
            self.encrypt_block(&mut block);
            tail.get_out().copy_from_slice(&block[..n]);
        }
    }

    /// Decrypt data using `InOutBuf`.
    fn decrypt_inout(mut self, data: InOutBuf<'_, '_, u8>)
    where
        Self: BlockModeDecrypt,
    {
        let (blocks, mut tail) = data.into_chunks();
        self.decrypt_blocks_inout(blocks);
        let n = tail.len();
        if n != 0 {
            let mut block = Block::<Self>::default();
            block[..n].copy_from_slice(tail.get_in());
            self.decrypt_block(&mut block);
            tail.get_out().copy_from_slice(&block[..n]);
        }
    }
    /// Encrypt data in place.
    fn encrypt(self, buf: &mut [u8])
    where
        Self: BlockModeEncrypt,
    {
        self.encrypt_inout(buf.into());
    }

    /// Decrypt data in place.
    fn decrypt(self, buf: &mut [u8])
    where
        Self: BlockModeDecrypt,
    {
        self.decrypt_inout(buf.into());
    }

    /// Encrypt data from buffer to buffer.
    ///
    /// # Errors
    /// Returns [`NotEqualError`] if provided `in_buf` and `out_buf` have different lengths.
    fn encrypt_b2b(self, in_buf: &[u8], out_buf: &mut [u8]) -> Result<(), NotEqualError>
    where
        Self: BlockModeEncrypt,
    {
        InOutBuf::new(in_buf, out_buf).map(|b| self.encrypt_inout(b))
    }

    /// Decrypt data from buffer to buffer.
    ///
    /// # Errors
    /// Returns [`NotEqualError`] if provided `in_buf` and `out_buf` have different lengths.
    fn decrypt_b2b(self, in_buf: &[u8], out_buf: &mut [u8]) -> Result<(), NotEqualError>
    where
        Self: BlockModeDecrypt,
    {
        InOutBuf::new(in_buf, out_buf).map(|b| self.decrypt_inout(b))
    }
}

/// Stream cipher trait.
///
/// This trait applies only to synchronous stream ciphers, which generate a keystream and
/// XOR data with it during both encryption and decryption. Therefore, instead of separate methods
/// for encryption and decryption, this trait provides methods for keystream application.
///
/// # Notes on Keystream Repetition
/// All stream ciphers have a finite state, so the generated keystream inevitably repeats itself,
/// making the cipher vulnerable to chosen plaintext attack. Typically, the repetition period is
/// astronomically large, rendering keystream repetition impossible to encounter in practice.
///
/// However, counter-based stream ciphers allow seeking across the keystream, and some also use
/// small counters (e.g. 32 bits). This can result in triggering keystream repetition in practice.
///
/// To guard against this, methods either panic (e.g. [`StreamCipher::apply_keystream`]) or
/// return [`StreamCipherError`] (e.g. [`StreamCipher::try_apply_keystream`]) when
/// keystream repetition occurs. We also provide a number of "unchecked" methods
/// (e.g. [`StreamCipher::unchecked_apply_keystream`]), but they should be used with extreme care.
///
/// For efficiency reasons, the check for keystream repetition is typically implemented by
/// forbidding the generation of the last keystream block in both the keystream application methods
/// and the seeking methods defined in the [`StreamCipherSeek`] trait.
pub trait StreamCipher {
    /// Check that the cipher can generate a keystream with a length of `data_len` bytes.
    ///
    /// # Errors
    /// Returns [`StreamCipherError`] in the event it cannot.
    fn check_remaining(&self, data_len: usize) -> Result<(), StreamCipherError>;

    /// Apply keystream to `inout` without checking for keystream repetition.
    ///
    /// <div><class = "warning">
    /// <b>WARNING<b>
    ///
    /// This method should be used with extreme caution! Triggering keystream repetition can expose
    /// the stream cipher to chosen plaintext attacks.
    /// </div>
    fn unchecked_apply_keystream_inout(&mut self, buf: InOutBuf<'_, '_, u8>);

    /// Apply keystream to `buf` without checking for keystream repetition.
    ///
    /// <div><class = "warning">
    /// <b>WARNING<b>
    ///
    /// This method should be used with extreme caution! Triggering keystream repetition can expose
    /// the stream cipher to chosen plaintext attacks.
    /// </div>
    fn unchecked_write_keystream(&mut self, buf: &mut [u8]);

    /// Apply keystream to data behind `buf` without checking for keystream repetition.
    ///
    /// <div><class = "warning">
    /// <b>WARNING<b>
    ///
    /// This method should be used with extreme caution! Triggering keystream repetition can expose
    /// the stream cipher to chosen plaintext attacks.
    /// </div>
    #[inline]
    fn unchecked_apply_keystream(&mut self, buf: &mut [u8]) {
        self.unchecked_apply_keystream_inout(buf.into());
    }

    /// Apply keystream to data buffer-to-buffer without checking for keystream repetition.
    ///
    /// It will XOR generated keystream with data from the `input` buffer
    /// and will write result to the `output` buffer.
    ///
    /// # Errors
    /// Returns [`NotEqualError`] if the `input` and `output` buffers have different lengths.
    ///
    /// <div><class = "warning">
    /// <b>WARNING<b>
    ///
    /// This method should be used with extreme caution! Triggering keystream repetition can expose
    /// the stream cipher to chosen plaintext attacks.
    /// </div>
    #[inline]
    fn unchecked_apply_keystream_b2b(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), NotEqualError> {
        let buf = InOutBuf::new(input, output)?;
        self.unchecked_apply_keystream_inout(buf);
        Ok(())
    }

    /// Apply keystream to `inout` data.
    ///
    /// # Errors
    /// If the end of the keystream is reached with the given buffer length,
    /// the method will return [`StreamCipherError`] without modifying `buf`.
    fn try_apply_keystream_inout(
        &mut self,
        buf: InOutBuf<'_, '_, u8>,
    ) -> Result<(), StreamCipherError> {
        self.check_remaining(buf.len())?;
        self.unchecked_apply_keystream_inout(buf);
        Ok(())
    }

    /// Apply keystream to data behind `buf`.
    ///
    /// # Errors
    /// If the end of the keystream is reached with the given buffer length,
    /// the method will return [`StreamCipherError`] without modifying `buf`.
    #[inline]
    fn try_apply_keystream(&mut self, buf: &mut [u8]) -> Result<(), StreamCipherError> {
        self.try_apply_keystream_inout(buf.into())
    }

    /// Apply keystream to data buffer-to-buffer.
    ///
    /// It will XOR generated keystream with data from the `input` buffer
    /// and will write result to the `output` buffer.
    ///
    /// # Errors
    /// Returns [`StreamCipherError`] without modifying the buffers if the `input` and `output`
    /// buffers have different lengths, or if the end of the keystream is reached with
    /// the given data length.
    #[inline]
    fn try_apply_keystream_b2b(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), StreamCipherError> {
        InOutBuf::new(input, output)
            .map_err(|_| StreamCipherError)
            .and_then(|buf| self.try_apply_keystream_inout(buf))
    }

    /// Write keystream to `buf`.
    ///
    /// # Errors
    /// If the end of the keystream is reached with the given buffer length,
    /// the method will return [`StreamCipherError`] without modifying `buf`.
    #[inline]
    fn try_write_keystream(&mut self, buf: &mut [u8]) -> Result<(), StreamCipherError> {
        self.check_remaining(buf.len())?;
        self.unchecked_write_keystream(buf);
        Ok(())
    }

    /// Apply keystream to `inout` data.
    ///
    /// It will XOR generated keystream with the data behind `in` pointer
    /// and will write result to `out` pointer.
    ///
    /// # Panics
    /// If the end of the keystream is reached with the given buffer length.
    #[inline]
    fn apply_keystream_inout(&mut self, buf: InOutBuf<'_, '_, u8>) {
        self.try_apply_keystream_inout(buf)
            .expect("end of keystream reached");
    }

    /// Apply keystream to data in-place.
    ///
    /// It will XOR generated keystream with `data` and will write result
    /// to the same buffer.
    ///
    /// # Panics
    /// If the end of the keystream is reached with the given buffer length.
    #[inline]
    fn apply_keystream(&mut self, buf: &mut [u8]) {
        self.try_apply_keystream(buf)
            .expect("end of keystream reached");
    }

    /// Apply keystream to data buffer-to-buffer.
    ///
    /// It will XOR generated keystream with data from the `input` buffer
    /// and will write result to the `output` buffer.
    ///
    /// # Panics
    /// If the end of the keystream is reached with the given buffer length,
    /// of if the `input` and `output` buffers have different lengths.
    #[inline]
    fn apply_keystream_b2b(&mut self, input: &[u8], output: &mut [u8]) {
        let Ok(buf) = InOutBuf::new(input, output) else {
            panic!("Lengths of input and output buffers are not equal to each other!");
        };
        self.apply_keystream_inout(buf);
    }

    /// Write keystream to `buf`.
    ///
    /// # Panics
    /// If the end of the keystream is reached with the given buffer length.
    #[inline]
    fn write_keystream(&mut self, buf: &mut [u8]) {
        self.try_write_keystream(buf)
            .expect("end of keystream reached");
    }
}

/// Trait for seekable stream ciphers.
///
/// Methods of this trait are generic over the [`SeekNum`] trait,
/// i.e. they can be used with `i32`, `u32`, `u64`, `u128`, and `usize`.
pub trait StreamCipherSeek {
    /// Try to get current keystream position in bytes.
    ///
    /// # Errors
    /// Returns [`OverflowError`] if the position value can not be represented by type `T`.
    fn try_current_pos<T: SeekNum>(&self) -> Result<T, OverflowError>;

    /// Try to seek to the provided position in bytes.
    ///
    /// # Errors
    /// Returns [`StreamCipherError`] if the position value is bigger than keystream length.
    fn try_seek<T: SeekNum>(&mut self, pos: T) -> Result<(), StreamCipherError>;

    /// Get current keystream position in bytes.
    ///
    /// # Panics
    /// If the position value can not be represented by type `T`.
    fn current_pos<T: SeekNum>(&self) -> T {
        self.try_current_pos()
            .expect("position cannot be represented by `T`")
    }

    /// Seek to the provided keystream position in bytes.
    ///
    /// # Panics
    /// If the position value is bigger than keystream length.
    fn seek<T: SeekNum>(&mut self, pos: T) {
        self.try_seek(pos)
            .expect("position value bigger than keystream length");
    }
}

impl<C: StreamCipher> StreamCipher for &mut C {
    #[inline]
    fn check_remaining(&self, data_len: usize) -> Result<(), StreamCipherError> {
        C::check_remaining(self, data_len)
    }

    #[inline]
    fn unchecked_apply_keystream_inout(&mut self, buf: InOutBuf<'_, '_, u8>) {
        C::unchecked_apply_keystream_inout(self, buf);
    }

    #[inline]
    fn unchecked_write_keystream(&mut self, buf: &mut [u8]) {
        C::unchecked_write_keystream(self, buf);
    }
}

/// Trait implemented for numeric types which can be used with the
/// [`StreamCipherSeek`] trait.
///
/// This trait is implemented for `i32`, `u32`, `u64`, `u128`, and `usize`.
/// It is not intended to be implemented in third-party crates.
pub trait SeekNum: Sized {
    /// Try to get position for block number `block`, byte position inside
    /// block `byte`, and block size `bs`.
    ///
    /// # Errors
    /// Returns [`OverflowError`] in the event of a counter overflow.
    fn from_block_byte<T: StreamCipherCounter>(
        block: T,
        byte: u8,
        bs: u8,
    ) -> Result<Self, OverflowError>;

    /// Try to get block number and bytes position for given block size `bs`.
    ///
    /// # Errors
    /// Returns [`OverflowError`] in the event of a counter overflow.
    fn into_block_byte<T: StreamCipherCounter>(self, bs: u8) -> Result<(T, u8), OverflowError>;
}

macro_rules! impl_seek_num {
    {$($t:ty )*} => {
        $(
            impl SeekNum for $t {
                fn from_block_byte<T: StreamCipherCounter>(block: T, byte: u8, block_size: u8) -> Result<Self, OverflowError> {
                    debug_assert!(byte != 0);
                    let rem = block_size.checked_sub(byte).ok_or(OverflowError)?;
                    let block: Self = block.try_into().map_err(|_| OverflowError)?;
                    block
                        .checked_mul(block_size.into())
                        .and_then(|v| v.checked_sub(rem.into()))
                        .ok_or(OverflowError)
                }

                fn into_block_byte<T: StreamCipherCounter>(self, block_size: u8) -> Result<(T, u8), OverflowError> {
                    let bs = Self::from(block_size);
                    let byte = u8::try_from(self % bs).expect("bs fits into u8");
                    let block = T::try_from(self / bs).map_err(|_| OverflowError)?;
                    Ok((block, byte))
                }
            }
        )*
    };
}

impl_seek_num! { i32 u32 u64 u128 usize }
