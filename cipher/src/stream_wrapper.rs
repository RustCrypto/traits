use crate::{
    errors::StreamCipherError, OverflowError, SeekNum, Block,
    StreamCipher, StreamCipherCore, StreamCipherSeek, StreamCipherSeekCore,
};
use inout::InOutBuf;
use crypto_common::{BlockSizeUser, Iv, IvSizeUser, Key, KeyInit, KeyIvInit, KeySizeUser};
use generic_array::typenum::Unsigned;

/// Wrapper around [`StreamCipherCore`] implementations.
///
/// It handles data buffering and implements the slice-based traits.
#[derive(Clone, Default)]
pub struct StreamCipherCoreWrapper<T: BlockSizeUser> {
    core: T,
    buffer: Block<T>,
    pos: usize,
}

impl<T: StreamCipherCore> StreamCipherCoreWrapper<T> {
    /// Return reference to the core type.
    pub fn get_core(&self) -> &T {
        &self.core
    }

    /// Return current cursor position.
    #[inline]
    fn get_pos(&self) -> usize {
        if self.pos >= T::BlockSize::USIZE {
            // SAFETY: `pos` is set only to values smaller than block size
            unsafe { core::hint::unreachable_unchecked() }
        }
        self.pos as usize
    }

    /// Return size of the internall buffer in bytes.
    #[inline]
    fn size(&self) -> usize {
        T::BlockSize::USIZE
    }

    #[inline]
    fn set_pos_unchecked(&mut self, pos: usize) {
        debug_assert!(pos < T::BlockSize::USIZE);
        self.pos = pos;
    }

    /// Return number of remaining bytes in the internall buffer.
    #[inline]
    fn remaining(&self) -> usize {
        self.size() - self.get_pos()
    }

    fn check_remaining(&self, dlen: usize) -> Result<(), StreamCipherError> {
        let rem_blocks = match self.core.remaining_blocks() {
            Some(v) => v,
            None => return Ok(()),
        };

        let bytes = if self.pos == 0 {
            dlen
        } else {
            let rem = self.remaining();
            if dlen > rem {
                dlen - rem
            } else {
                return Ok(());
            }
        };
        let bs = T::BlockSize::USIZE;
        let blocks = if bytes % bs == 0 {
            bytes / bs
        } else {
            bytes / bs + 1
        };
        if blocks > rem_blocks {
            Err(StreamCipherError)
        } else {
            Ok(())
        }
    }
}

impl<T: StreamCipherCore> StreamCipher for StreamCipherCoreWrapper<T> {
    #[inline]
    fn try_apply_keystream(&mut self, mut data: InOutBuf<'_, u8>) -> Result<(), StreamCipherError> {
        self.check_remaining(data.len())?;

        let pos = self.get_pos();
        let r = self.remaining();
        let n = data.len();
        if pos != 0 {
            if n < r {
                // double slicing allows to remove panic branches
                data.xor(&self.buffer[pos..][..n]);
                self.set_pos_unchecked(pos + n);
                return Ok(());
            }
            let (mut left, right) = data.split_at(r);
            data = right;
            left.xor(&self.buffer[pos..]);
        }

        let (blocks, mut leftover) = data.into_chunks();
        self.core.apply_keystream_blocks(blocks, |_| {}, |_| {});

        let n = leftover.len();
        if n != 0 {
            let mut block = Default::default();
            self.core.apply_keystream_blocks(
                InOutBuf::from_mut(&mut block),
                |_| {},
                |_| {},
            );
            leftover.xor(&block[..n]);
            self.buffer = block;
        }
        self.set_pos_unchecked(n);

        Ok(())
    }
}

impl<T: StreamCipherSeekCore> StreamCipherSeek for StreamCipherCoreWrapper<T> {
    fn try_current_pos<SN: SeekNum>(&self) -> Result<SN, OverflowError> {
        let Self { core, pos, .. } = self;
        let bs = T::BlockSize::USIZE;
        SN::from_block_byte(core.get_block_pos(), *pos, bs)
    }

    fn try_seek<SN: SeekNum>(&mut self, new_pos: SN) -> Result<(), StreamCipherError> {
        let Self { core, buffer, pos } = self;
        let bs = T::BlockSize::USIZE;
        let (block_pos, byte_pos) = new_pos.into_block_byte(bs)?;
        core.set_block_pos(block_pos);
        if byte_pos != 0 {
            let mut block = Default::default();
            let buf = InOutBuf::from_mut(&mut block);
            core.apply_keystream_blocks(buf, |_| {}, |_| {});
            *buffer = block;
        }
        *pos = byte_pos;
        Ok(())
    }
}

// Note: ideally we would only implement the InitInner trait and everything
// else would be handled by blanket impls, but unfortunately it will
// not work properly without mutually exclusive traits, see:
// https://github.com/rust-lang/rfcs/issues/1053

impl<T: KeySizeUser + BlockSizeUser> KeySizeUser for StreamCipherCoreWrapper<T> {
    type KeySize = T::KeySize;
}

impl<T: IvSizeUser + BlockSizeUser> IvSizeUser for StreamCipherCoreWrapper<T> {
    type IvSize = T::IvSize;
}

impl<T: KeyIvInit + BlockSizeUser> KeyIvInit for StreamCipherCoreWrapper<T> {
    #[inline]
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        Self {
            core: T::new(key, iv),
            buffer: Default::default(),
            pos: 0,
        }
    }
}

impl<T: KeyInit + BlockSizeUser> KeyInit for StreamCipherCoreWrapper<T> {
    #[inline]
    fn new(key: &Key<Self>) -> Self {
        Self {
            core: T::new(key),
            buffer: Default::default(),
            pos: 0,
        }
    }
}
