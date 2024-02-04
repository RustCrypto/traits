use crate::{
    errors::StreamCipherError, OverflowError, SeekNum, StreamCipher, StreamCipherCore,
    StreamCipherSeek, StreamCipherSeekCore,
};
use core::fmt;
use crypto_common::{
    typenum::Unsigned, Iv, IvSizeUser, Key, KeyInit, KeyIvInit, KeySizeUser, ParBlocks,
};
use inout::InOutBuf;
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Buffering wrapper around a [`StreamCipherCore`] implementation.
///
/// It handles data buffering and implements the slice-based traits.
pub struct StreamCipherCoreWrapper<T: StreamCipherCore> {
    core: T,
    // First byte is used as position
    // First block is used as a small buffer, the rest is to be used by
    // ApplyBlocksCtx
    buffer: ParBlocks<T>,
}

impl<T: StreamCipherCore + Default> Default for StreamCipherCoreWrapper<T> {
    #[inline]
    fn default() -> Self {
        Self::from_core(T::default())
    }
}

impl<T: StreamCipherCore + Clone> Clone for StreamCipherCoreWrapper<T> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            core: self.core.clone(),
            buffer: self.buffer.clone(),
        }
    }
}

impl<T: StreamCipherCore + fmt::Debug> fmt::Debug for StreamCipherCoreWrapper<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pos = self.get_pos().into();
        let buf_data = &self.buffer[pos..];
        f.debug_struct("StreamCipherCoreWrapper")
            .field("core", &self.core)
            .field("buffer_data", &buf_data)
            .finish()
    }
}

impl<T: StreamCipherCore> StreamCipherCoreWrapper<T> {
    /// Return reference to the core type.
    pub fn get_core(&self) -> &T {
        &self.core
    }

    /// Return reference to the core type.
    pub fn from_core(core: T) -> Self {
        let mut buffer: ParBlocks<T> = Default::default();
        buffer[0][0] = T::BlockSize::U8;
        Self { core, buffer }
    }

    /// Return current cursor position.
    #[inline]
    fn get_pos(&self) -> u8 {
        let pos = self.buffer[0][0];
        if pos == 0 || pos > T::BlockSize::U8 {
            debug_assert!(false);
            // SAFETY: `pos` never breaks the invariant
            unsafe {
                core::hint::unreachable_unchecked();
            }
        }
        pos
    }

    /// Set buffer position without checking that it's smaller
    /// than buffer size.
    ///
    /// # Safety
    /// `pos` MUST be bigger than zero and smaller or equal to `T::BlockSize::USIZE`.
    #[inline]
    unsafe fn set_pos_unchecked(&mut self, pos: usize) {
        debug_assert!(pos != 0 && pos <= T::BlockSize::USIZE);
        // Block size is always smaller than 256 because of the `BlockSizes` bound,
        // so if the safety condition is satisfied, the `as` cast does not truncate
        // any non-zero bits.
        self.buffer[0][0] = pos as u8;
    }

    /// Return number of remaining bytes in the internal buffer.
    #[inline]
    fn remaining(&self) -> u8 {
        // This never underflows because of the safety invariant
        T::BlockSize::U8 - self.get_pos()
    }

    fn check_remaining(&self, data_len: usize) -> Result<(), StreamCipherError> {
        let rem_blocks = match self.core.remaining_blocks() {
            Some(v) => v,
            None => return Ok(()),
        };

        let buf_rem = usize::from(self.remaining());
        let data_len = match data_len.checked_sub(buf_rem) {
            Some(0) | None => return Ok(()),
            Some(res) => res,
        };

        let bs = T::BlockSize::USIZE;
        // TODO: use div_ceil on 1.73+ MSRV bump
        let blocks = (data_len + bs - 1) / bs;
        if blocks > rem_blocks {
            Err(StreamCipherError)
        } else {
            Ok(())
        }
    }
}

impl<T: StreamCipherCore> StreamCipher for StreamCipherCoreWrapper<T> {
    #[inline]
    fn try_apply_keystream_inout(
        &mut self,
        mut data: InOutBuf<'_, '_, u8>,
    ) -> Result<(), StreamCipherError> {
        self.check_remaining(data.len())?;

        let pos = usize::from(self.get_pos());
        let rem = usize::from(self.remaining());
        let data_len = data.len();

        if rem != 0 {
            if data_len <= rem {
                data.xor_in2out(&self.buffer[0][pos..][..data_len]);
                // SAFETY: we have checked that `data_len` is less or equal to length
                // of remaining keystream data, thus `pos + data_len` can not be bigger
                // than block size. Since `pos` is never zero, `pos + data_len` can not
                // be zero. Thus `pos + data_len` satisfies the safety invariant required
                // by `set_pos_unchecked`.
                unsafe {
                    self.set_pos_unchecked(pos + data_len);
                }
                return Ok(());
            }
            let (mut left, right) = data.split_at(rem);
            data = right;
            left.xor_in2out(&self.buffer[0][pos..]);
        }

        let (blocks, mut tail) = data.into_chunks();

        let (chunks, mut tail_blocks) = blocks.into_chunks::<T::ParBlocksSize>();

        for mut chunk in chunks {
            self.core.write_keystream_blocks(&mut self.buffer);
            chunk.xor_in2out(&self.buffer);
        }
        let n = tail_blocks.len();
        self.core
            .write_keystream_blocks(&mut self.buffer[..tail_blocks.len()]);
        for i in 0..n {
            tail_blocks.get(i).xor_in2out(&self.buffer[i]);
        }

        let new_pos = if tail.is_empty() {
            T::BlockSize::USIZE
        } else {
            // Note that we temporarily write a pseudo-random byte into
            // the first byte of `self.buffer`. It may break the safety invariant,
            // but after XORing keystream block with `tail`, we immediately
            // overwrite the first byte with a correct value.
            self.core.write_keystream_block(&mut self.buffer[0]);
            tail.xor_in2out(&self.buffer[0][..tail.len()]);
            tail.len()
        };

        // SAFETY: `into_chunks` always returns tail with size
        // less than block size. If `tail.len()` is zero, we replace
        // it with block size. Thus the invariant required by
        // `set_pos_unchecked` is satisfied.
        unsafe {
            self.set_pos_unchecked(new_pos);
        }

        Ok(())
    }
}

impl<T: StreamCipherSeekCore> StreamCipherSeek for StreamCipherCoreWrapper<T> {
    fn try_current_pos<SN: SeekNum>(&self) -> Result<SN, OverflowError> {
        let pos = self.get_pos();
        SN::from_block_byte(self.core.get_block_pos(), pos, T::BlockSize::U8)
    }

    fn try_seek<SN: SeekNum>(&mut self, new_pos: SN) -> Result<(), StreamCipherError> {
        let (block_pos, byte_pos) = new_pos.into_block_byte(T::BlockSize::U8)?;
        // For correct implementations of `SeekNum` compiler should be able to
        // eliminate this assert
        assert!(byte_pos < T::BlockSize::U8);

        self.core.set_block_pos(block_pos);
        let new_pos = if byte_pos != 0 {
            // See comment in `try_apply_keystream_inout` for use of `write_keystream_block`
            self.core.write_keystream_block(&mut self.buffer[0]);
            byte_pos.into()
        } else {
            T::BlockSize::USIZE
        };
        // SAFETY: we assert that `byte_pos` is always smaller than block size.
        // If `byte_pos` is zero, we replace it with block size. Thus the invariant
        // required by `set_pos_unchecked` is satisfied.
        unsafe {
            self.set_pos_unchecked(new_pos);
        }
        Ok(())
    }
}

// Note: ideally we would only implement the InitInner trait and everything
// else would be handled by blanket impls, but, unfortunately, it will
// not work properly without mutually exclusive traits, see:
// https://github.com/rust-lang/rfcs/issues/1053

impl<T: KeySizeUser + StreamCipherCore> KeySizeUser for StreamCipherCoreWrapper<T> {
    type KeySize = T::KeySize;
}

impl<T: IvSizeUser + StreamCipherCore> IvSizeUser for StreamCipherCoreWrapper<T> {
    type IvSize = T::IvSize;
}

impl<T: KeyIvInit + StreamCipherCore> KeyIvInit for StreamCipherCoreWrapper<T> {
    #[inline]
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        let mut buffer = ParBlocks::<T>::default();
        buffer[0][0] = T::BlockSize::U8;
        Self {
            core: T::new(key, iv),
            buffer,
        }
    }
}

impl<T: KeyInit + StreamCipherCore> KeyInit for StreamCipherCoreWrapper<T> {
    #[inline]
    fn new(key: &Key<Self>) -> Self {
        let mut buffer = ParBlocks::<T>::default();
        buffer[0][0] = T::BlockSize::U8;
        Self {
            core: T::new(key),
            buffer,
        }
    }
}

#[cfg(feature = "zeroize")]
impl<T: StreamCipherCore> Drop for StreamCipherCoreWrapper<T> {
    fn drop(&mut self) {
        // If present, `core` will be zeroized by its own `Drop`.
        self.buffer.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<T: StreamCipherCore + ZeroizeOnDrop> ZeroizeOnDrop for StreamCipherCoreWrapper<T> {}
