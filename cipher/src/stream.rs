//! Traits which define functionality of stream ciphers.
//!
//! See [RustCrypto/stream-ciphers](https://github.com/RustCrypto/stream-ciphers)
//! for ciphers implementation.

use crate::errors::{LoopError, OverflowError};
use core::convert::{TryFrom, TryInto};
use generic_array::typenum::U1;
use crate::inout::{InOutBuf, InResOutBuf};
use crypto_common::{BlockProcessing, Block};

/// Synchronous stream ciphers.
pub trait StreamCipherCore: BlockProcessing {
    /// Generate next keystream block.
    fn gen_keystream_block(&mut self) -> Result<Block<Self>, LoopError>;

    /// Generate keystream blocks in parallel for provided data blocks.
    fn gen_keystream_blocks(
        &mut self,
        mut blocks: InOutBuf<'_, '_, Block<Self>>,
        proc: impl FnMut(InResOutBuf<'_, '_, '_, Block<Self>>),
    ) -> Result<(), LoopError> {
        blocks.try_chunks::<U1, LoopError, _, _, _, _>(
            self,
            |state, _, res| state.gen_keystream_block().map(|b| res[0] = b),
            |state, _, res| state.gen_keystream_block().map(|b| res[0] = b),
            proc,
        )
    }
}

/// Counter-based synchronous stream ciphers.
///
/// Such ciphers allow random access to an underlying keystream and can return
/// current position in it.
pub trait CounterStreamCipherCore: StreamCipherCore {
    type Counter;

    /// Get current block position.
    fn get_block_pos(&self) -> Self::Counter;

    /// Set current block position.
    fn set_block_pos(&mut self, pos: Self::Counter);
}

/// Synchronous stream cipher core trait.
pub trait StreamCipher {
    /// Apply keystream to the data.
    ///
    /// It will XOR generated keystream with the data, which can be both
    /// encryption and decryption.
    ///
    /// # Panics
    /// If end of the keystream will be reached with the given data length,
    /// method will panic without modifying the provided `data`.
    #[inline]
    fn apply_keystream(&mut self, data: &mut [u8]) {
        self.try_apply_keystream(data).unwrap();
    }

    /// Apply keystream to the data, but return an error if end of a keystream
    /// will be reached.
    ///
    /// If end of the keystream will be achieved with the given data length,
    /// method will return `Err(LoopError)` without modifying provided `data`.
    fn try_apply_keystream(&mut self, data: &mut [u8]) -> Result<(), LoopError>;
}

/// Trait for seekable stream ciphers.
///
/// Methods of this trait are generic over the [`SeekNum`] trait, which is
/// implemented for primitive numeric types, i.e.: `i/u8`, `i/u16`, `i/u32`,
/// `i/u64`, `i/u128`, and `i/usize`.
pub trait StreamCipherSeek {
    /// Try to get current keystream position
    ///
    /// Returns [`LoopError`] if position can not be represented by type `T`
    fn try_current_pos<T: SeekNum>(&self) -> Result<T, OverflowError>;

    /// Try to seek to the given position
    ///
    /// Returns [`LoopError`] if provided position value is bigger than
    /// keystream length.
    fn try_seek<T: SeekNum>(&mut self, pos: T) -> Result<(), LoopError>;

    /// Get current keystream position
    ///
    /// # Panics
    /// If position can not be represented by type `T`
    fn current_pos<T: SeekNum>(&self) -> T {
        self.try_current_pos().unwrap()
    }

    /// Seek to the given position
    ///
    /// # Panics
    /// If provided position value is bigger than keystream leangth
    fn seek<T: SeekNum>(&mut self, pos: T) {
        self.try_seek(pos).unwrap()
    }
}

/// Asynchronous stream cipher core trait.
pub trait AsyncStreamCipher {
    /// Encrypt data in place.
    fn encrypt(&mut self, data: &mut [u8]);

    /// Decrypt data in place.
    fn decrypt(&mut self, data: &mut [u8]);
}

impl<C: StreamCipher> StreamCipher for &mut C {
    #[inline]
    fn apply_keystream(&mut self, data: &mut [u8]) {
        C::apply_keystream(self, data);
    }

    #[inline]
    fn try_apply_keystream(&mut self, data: &mut [u8]) -> Result<(), LoopError> {
        C::try_apply_keystream(self, data)
    }
}

/// Trait implemented for numeric types which can be used with the
/// [`StreamCipherSeek`] trait.
///
/// This trait is implemented for primitive numeric types, i.e. `i/u8`,
/// `u16`, `u32`, `u64`, `u128`, `usize`, and `i32`. It is not intended
/// to be implemented in third-party crates.
#[rustfmt::skip]
pub trait SeekNum:
    Sized
    + TryInto<u8> + TryFrom<u8> + TryInto<i8> + TryFrom<i8>
    + TryInto<u16> + TryFrom<u16> + TryInto<i16> + TryFrom<i16>
    + TryInto<u32> + TryFrom<u32> + TryInto<i32> + TryFrom<i32>
    + TryInto<u64> + TryFrom<u64> + TryInto<i64> + TryFrom<i64>
    + TryInto<u128> + TryFrom<u128> + TryInto<i128> + TryFrom<i128>
    + TryInto<usize> + TryFrom<usize> + TryInto<isize> + TryFrom<isize>
{
    /// Try to get position for block number `block`, byte position inside
    /// block `byte`, and block size `bs`.
    fn from_block_byte<T: SeekNum>(block: T, byte: u8, bs: u8) -> Result<Self, OverflowError>;

    /// Try to get block number and bytes position for given block size `bs`.
    fn to_block_byte<T: SeekNum>(self, bs: u8) -> Result<(T, u8), OverflowError>;
}

macro_rules! impl_seek_num {
    {$($t:ty )*} => {
        $(
            impl SeekNum for $t {
                fn from_block_byte<T: TryInto<Self>>(block: T, byte: u8, bs: u8) -> Result<Self, OverflowError> {
                    debug_assert!(byte < bs);
                    let block = block.try_into().map_err(|_| OverflowError)?;
                    let pos = block.checked_mul(bs as Self).ok_or(OverflowError)? + (byte as Self);
                    Ok(pos)
                }

                fn to_block_byte<T: TryFrom<Self>>(self, bs: u8) -> Result<(T, u8), OverflowError> {
                    let bs = bs as Self;
                    let byte = self % bs;
                    let block = T::try_from(self/bs).map_err(|_| OverflowError)?;
                    Ok((block, byte as u8))
                }
            }
        )*
    };
}

impl_seek_num! { u8 u16 u32 u64 u128 usize i32 }
