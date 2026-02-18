use crate::StreamCipherCounter;

use super::{
    OverflowError, SeekNum, StreamCipher, StreamCipherCore, StreamCipherSeek, StreamCipherSeekCore,
    errors::StreamCipherError,
};
use block_buffer::{BlockSizes, ReadBuffer};
use common::{
    Iv, IvSizeUser, Key, KeyInit, KeyIvInit, KeySizeUser, array::Array, typenum::Unsigned,
};
use core::fmt;
use inout::InOutBuf;
#[cfg(feature = "zeroize")]
use zeroize::ZeroizeOnDrop;

/// Buffering wrapper around a [`StreamCipherCore`] implementation.
///
/// It handles data buffering and implements the slice-based traits.
pub struct StreamCipherCoreWrapper<T>
where
    T: StreamCipherCore,
    T::BlockSize: BlockSizes,
{
    core: T,
    buffer: ReadBuffer<T::BlockSize>,
}

impl<T> Clone for StreamCipherCoreWrapper<T>
where
    T: StreamCipherCore + Clone,
    T::BlockSize: BlockSizes,
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            core: self.core.clone(),
            buffer: self.buffer.clone(),
        }
    }
}

impl<T> fmt::Debug for StreamCipherCoreWrapper<T>
where
    T: StreamCipherCore + fmt::Debug,
    T::BlockSize: BlockSizes,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamCipherCoreWrapper")
            .finish_non_exhaustive()
    }
}

impl<T> StreamCipherCoreWrapper<T>
where
    T: StreamCipherCore,
    T::BlockSize: BlockSizes,
{
    /// Initialize from a [`StreamCipherCore`] instance.
    pub fn from_core(core: T) -> Self {
        Self {
            core,
            buffer: Default::default(),
        }
    }

    /// Get reference to the wrapped [`StreamCipherCore`] instance.
    pub fn get_core(&self) -> &T {
        &self.core
    }
}

impl<T> StreamCipher for StreamCipherCoreWrapper<T>
where
    T: StreamCipherCore,
    T::BlockSize: BlockSizes,
{
    #[inline]
    fn check_remaining(&self, data_len: usize) -> Result<(), StreamCipherError> {
        let Some(rem_blocks) = self.core.remaining_blocks() else {
            return Ok(());
        };
        let Some(data_len) = data_len.checked_sub(self.buffer.remaining()) else {
            return Ok(());
        };
        let req_blocks = data_len.div_ceil(T::BlockSize::USIZE);
        if req_blocks > rem_blocks {
            Err(StreamCipherError)
        } else {
            Ok(())
        }
    }

    #[inline]
    fn unchecked_apply_keystream_inout(&mut self, data: InOutBuf<'_, '_, u8>) {
        let head_ks = self.buffer.read_cached(data.len());

        let (mut head, data) = data.split_at(head_ks.len());
        let (blocks, mut tail) = data.into_chunks();

        head.xor_in2out(head_ks);
        self.core.apply_keystream_blocks_inout(blocks);

        self.buffer.write_block(
            tail.len(),
            |b| self.core.write_keystream_block(b),
            |tail_ks| {
                tail.xor_in2out(tail_ks);
            },
        );
    }

    #[inline]
    fn unchecked_write_keystream(&mut self, data: &mut [u8]) {
        let head_ks = self.buffer.read_cached(data.len());

        let (head, data) = data.split_at_mut(head_ks.len());
        let (blocks, tail) = Array::slice_as_chunks_mut(data);

        head.copy_from_slice(head_ks);
        self.core.write_keystream_blocks(blocks);

        self.buffer.write_block(
            tail.len(),
            |b| self.core.write_keystream_block(b),
            |tail_ks| tail.copy_from_slice(tail_ks),
        );
    }
}

impl<T> StreamCipherSeek for StreamCipherCoreWrapper<T>
where
    T: StreamCipherSeekCore,
    T::BlockSize: BlockSizes,
{
    #[allow(clippy::unwrap_in_result)]
    fn try_current_pos<SN: SeekNum>(&self) -> Result<SN, OverflowError> {
        let pos = u8::try_from(self.buffer.get_pos())
            .expect("buffer position is always smaller than 256");
        SN::from_block_byte(self.core.get_block_pos(), pos, T::BlockSize::U8)
    }

    fn try_seek<SN: SeekNum>(&mut self, new_pos: SN) -> Result<(), StreamCipherError> {
        let (block_pos, byte_pos) = new_pos.into_block_byte::<T::Counter>(T::BlockSize::U8)?;
        if byte_pos != 0 && block_pos.is_max() {
            return Err(StreamCipherError);
        }
        // For correct implementations of `SeekNum` the compiler should be able to
        // eliminate this assert
        assert!(byte_pos < T::BlockSize::U8);

        self.core.set_block_pos(block_pos);

        self.buffer.reset();

        self.buffer.write_block(
            usize::from(byte_pos),
            |b| self.core.write_keystream_block(b),
            |_| {},
        );
        Ok(())
    }
}

// Note: ideally we would only implement the InitInner trait and everything
// else would be handled by blanket impls, but, unfortunately, it will
// not work properly without mutually exclusive traits, see:
// https://github.com/rust-lang/rfcs/issues/1053

impl<T> KeySizeUser for StreamCipherCoreWrapper<T>
where
    T: KeySizeUser + StreamCipherCore,
    T::BlockSize: BlockSizes,
{
    type KeySize = T::KeySize;
}

impl<T> IvSizeUser for StreamCipherCoreWrapper<T>
where
    T: IvSizeUser + StreamCipherCore,
    T::BlockSize: BlockSizes,
{
    type IvSize = T::IvSize;
}

impl<T> KeyIvInit for StreamCipherCoreWrapper<T>
where
    T: KeyIvInit + StreamCipherCore,
    T::BlockSize: BlockSizes,
{
    #[inline]
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        Self {
            core: T::new(key, iv),
            buffer: Default::default(),
        }
    }
}

impl<T> KeyInit for StreamCipherCoreWrapper<T>
where
    T: KeyInit + StreamCipherCore,
    T::BlockSize: BlockSizes,
{
    #[inline]
    fn new(key: &Key<Self>) -> Self {
        Self {
            core: T::new(key),
            buffer: Default::default(),
        }
    }
}

#[cfg(feature = "zeroize")]
impl<T> ZeroizeOnDrop for StreamCipherCoreWrapper<T>
where
    T: StreamCipherCore + ZeroizeOnDrop,
    T::BlockSize: BlockSizes,
{
}

// Assert that `ReadBuffer` implements `ZeroizeOnDrop`
#[cfg(feature = "zeroize")]
const _: () = {
    #[allow(dead_code, trivial_casts)]
    fn check_buffer<BS: BlockSizes>(v: &ReadBuffer<BS>) {
        let _ = v as &dyn ZeroizeOnDrop;
    }
};
