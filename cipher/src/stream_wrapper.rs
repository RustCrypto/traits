use crate::{
    errors::StreamCipherError, Block, OverflowError, SeekNum, StreamCipher, StreamCipherCore,
    StreamCipherSeek, StreamCipherSeekCore,
};
use core::fmt;
use crypto_common::{typenum::Unsigned, Iv, IvSizeUser, Key, KeyInit, KeyIvInit, KeySizeUser};
use inout::InOutBuf;
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Wrapper around [`StreamCipherCore`] implementations.
///
/// It handles data buffering and implements the slice-based traits.
pub struct StreamCipherCoreWrapper<T: StreamCipherCore> {
    core: T,
    // First byte is used as position
    buffer: Block<T>,
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
        let pos = self.get_pos();
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
        let mut buffer = Block::<T>::default();
        buffer[0] = T::BlockSize::U8;
        Self { core, buffer }
    }

    /// Return current cursor position.
    #[inline]
    fn get_pos(&self) -> usize {
        let pos = self.buffer[0];
        if pos == 0 || pos > T::BlockSize::U8 {
            debug_assert!(false);
            // SAFETY: `pos` never breaks the invariant
            unsafe {
                core::hint::unreachable_unchecked();
            }
        }
        pos as usize
    }

    /// Return size of the internal buffer in bytes.
    #[inline]
    fn size(&self) -> usize {
        T::BlockSize::USIZE
    }

    /// Return number of remaining bytes in the internal buffer.
    #[inline]
    fn remaining(&self) -> usize {
        self.size() - self.get_pos()
    }

    #[inline]
    fn set_pos_unchecked(&mut self, pos: usize) {
        debug_assert!(pos != 0 && pos <= T::BlockSize::USIZE);
        self.buffer[0] = pos as u8;
    }

    #[inline]
    fn check_remaining(&self, data_len: usize) -> Result<(), StreamCipherError> {
        let rem_blocks = match self.core.remaining_blocks() {
            Some(v) => v,
            None => return Ok(()),
        };

        let buf_rem = self.remaining();
        if data_len <= buf_rem {
            return Ok(());
        }
        let data_len = data_len - buf_rem;

        let bs = T::BlockSize::USIZE;
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

        let pos = self.get_pos();
        let r = self.remaining();
        let n = data.len();

        if r != 0 {
            if n < r {
                data.xor_in2out(&self.buffer[pos..][..n]);
                self.set_pos_unchecked(pos + n);
                return Ok(());
            }
            let (mut left, right) = data.split_at(r);
            data = right;
            left.xor_in2out(&self.buffer[pos..]);
        }

        let (blocks, mut leftover) = data.into_chunks();
        self.core.apply_keystream_blocks_inout(blocks);

        let n = leftover.len();
        if n != 0 {
            self.core.write_keystream_block(&mut self.buffer);
            leftover.xor_in2out(&self.buffer[..n]);
            self.set_pos_unchecked(n);
        } else {
            self.set_pos_unchecked(T::BlockSize::USIZE);
        }

        Ok(())
    }
}

impl<T: StreamCipherSeekCore> StreamCipherSeek for StreamCipherCoreWrapper<T> {
    fn try_current_pos<SN: SeekNum>(&self) -> Result<SN, OverflowError> {
        let pos = self.get_pos() as u8;
        SN::from_block_byte(self.core.get_block_pos(), pos, T::BlockSize::U8)
    }

    fn try_seek<SN: SeekNum>(&mut self, new_pos: SN) -> Result<(), StreamCipherError> {
        let (block_pos, byte_pos) = new_pos.into_block_byte(T::BlockSize::U8)?;
        self.core.set_block_pos(block_pos);
        if byte_pos != T::BlockSize::U8 {
            self.core.write_keystream_block(&mut self.buffer);
        }
        self.set_pos_unchecked(byte_pos.into());
        Ok(())
    }
}

// Note: ideally we would only implement the InitInner trait and everything
// else would be handled by blanket impls, but unfortunately it will
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
        Self::from_core(T::new(key, iv))
    }
}

impl<T: KeyInit + StreamCipherCore> KeyInit for StreamCipherCoreWrapper<T> {
    #[inline]
    fn new(key: &Key<Self>) -> Self {
        Self::from_core(T::new(key))
    }
}

#[cfg(feature = "zeroize")]
impl<T: StreamCipherCore> Drop for StreamCipherCoreWrapper<T> {
    #[inline]
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<T: ZeroizeOnDrop + StreamCipherCore> ZeroizeOnDrop for StreamCipherCoreWrapper<T> {}
