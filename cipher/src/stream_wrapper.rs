use crate::{
    errors::StreamCipherError, AsyncStreamCipher, AsyncStreamCipherCore, OverflowError, SeekNum,
    StreamCipher, StreamCipherCore, StreamCipherSeek, StreamCipherSeekCore,
};
use block_buffer::{inout::InOutBuf, BlockBuffer};
use crypto_common::{BlockSizeUser, KeyIvInit, Key, Iv, KeySizeUser, IvSizeUser, KeyInit};
use generic_array::typenum::Unsigned;

/// Wrapper around [`StreamCipherCore`] implementations.
///
/// It handles data buffering and implements the slice-based traits.
#[derive(Clone, Default)]
pub struct StreamCipherCoreWrapper<T: BlockSizeUser> {
    core: T,
    buffer: BlockBuffer<T::BlockSize>,
}

impl<T: BlockSizeUser> StreamCipherCoreWrapper<T> {
    /// Get reference to core.
    pub fn get_core(&self) -> &T {
        &self.core
    }

    /// Split wrapper into core and buffer.
    pub fn into_inner(self) -> (T, BlockBuffer<T::BlockSize>) {
        (self.core, self.buffer)
    }

    /// Create wrapper from core and buffer.
    pub fn from_inner(core: T, buffer: BlockBuffer<T::BlockSize>) -> Self {
        Self { core, buffer }
    }
}

impl<T: StreamCipherCore> StreamCipher for StreamCipherCoreWrapper<T> {
    #[inline]
    fn try_apply_keystream(&mut self, data: InOutBuf<'_, u8>) -> Result<(), StreamCipherError> {
        if let Some(rem_blocks) = self.core.remaining_blocks() {
            let bytes = if self.buffer.get_pos() == 0 {
                data.len()
            } else {
                data.len() - self.buffer.remaining()
            };
            let bs = T::BlockSize::USIZE;
            let blocks = if bytes % bs == 0 {
                bytes / bs
            } else {
                bytes / bs + 1
            };
            if blocks > rem_blocks {
                return Err(StreamCipherError);
            }
        }

        let Self { core, buffer } = self;
        buffer.xor_data(data, |blocks| {
            core.apply_keystream_blocks(blocks, |_| {}, |_| {})
        });

        Ok(())
    }
}

impl<T: AsyncStreamCipherCore> AsyncStreamCipher for StreamCipherCoreWrapper<T> {
    #[inline]
    fn encrypt_inout(&mut self, data: InOutBuf<'_, u8>) {
        let Self { core, buffer } = self;
        buffer.xor_data(data, |blocks| core.encrypt_blocks_inout_mut(blocks, |_| {}));
    }

    #[inline]
    fn decrypt_inout(&mut self, data: InOutBuf<'_, u8>) {
        let Self { core, buffer } = self;
        buffer.xor_data(data, |blocks| core.decrypt_blocks_inout_mut(blocks, |_| {}));
    }
}

impl<T: StreamCipherSeekCore> StreamCipherSeek for StreamCipherCoreWrapper<T> {
    fn try_current_pos<SN: SeekNum>(&self) -> Result<SN, OverflowError> {
        let Self { core, buffer } = self;
        let bs = T::BlockSize::USIZE;
        SN::from_block_byte(core.get_block_pos(), buffer.get_pos(), bs)
    }

    fn try_seek<SN: SeekNum>(&mut self, pos: SN) -> Result<(), StreamCipherError> {
        let Self { core, buffer } = self;
        let bs = T::BlockSize::USIZE;
        let (block_pos, byte_pos) = pos.into_block_byte(bs)?;
        core.set_block_pos(block_pos);
        let mut block = Default::default();
        if byte_pos != 0 {
            let buf = InOutBuf::from_mut(&mut block);
            core.apply_keystream_blocks(buf, |_| {}, |_| {});
        }
        buffer.set(block, byte_pos);
        Ok(())
    }
}

// ideally we would only implement the InitInner trait and everythin else
// would be handled by blanket impls, but unfortunately it will not work
// properly without mutually exclusive traits

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
        }
    }
}

impl<T: KeyInit + BlockSizeUser> KeyInit for StreamCipherCoreWrapper<T> {
    #[inline]
    fn new(key: &Key<Self>) -> Self {
        Self {
            core: T::new(key),
            buffer: Default::default(),
        }
    }
}
