use crate::{BlockDecryptMut, BlockEncryptMut};
use block_buffer::{generic_array::typenum::Unsigned, inout::InOutBuf};
use core::convert::{TryFrom, TryInto};
use crypto_common::{Block, BlockUser};

/// Marker trait for block-level asynchronous stream ciphers
pub trait AsyncStreamCipherCore: BlockEncryptMut + BlockDecryptMut {}

/// Block-level synchronous stream ciphers.
pub trait StreamCipherCore: BlockUser + Sized {
    /// Return number of remaining blocks before cipher wraps around.
    ///
    /// Returns `None` if number of remaining blocks can not be computed
    /// (e.g. in ciphers based on the sponge construction) or it's too big
    /// to fit to `usize`.
    fn remaining_blocks(&self) -> Option<usize>;

    /// Apply keystream blocks with pre and post callbacks using
    /// parallel block processing if possible.
    ///
    /// WARNING: this method does not check number of remaining blocks!
    fn apply_keystream_blocks(
        &mut self,
        blocks: InOutBuf<'_, Block<Self>>,
        pre_fn: impl FnMut(&[Block<Self>]),
        post_fn: impl FnMut(&[Block<Self>]),
    );

    /// Apply keystream to data not divided into blocks.
    ///
    /// Consumes cipher since it may consume final keystream block only
    /// partially.
    ///
    /// WARNING: this method does not check number of remaining blocks!
    fn apply_keystream_partial(mut self, mut buf: InOutBuf<'_, u8>) {
        if buf.len() > Self::BlockSize::USIZE {
            let (blocks, tail) = buf.into_chunks();
            self.apply_keystream_blocks(blocks, |_| {}, |_| {});
            buf = tail;
        }
        let n = buf.len();
        let mut block = Block::<Self>::default();
        block[..n].copy_from_slice(buf.get_in());
        let mut t = InOutBuf::from_mut(&mut block);
        self.apply_keystream_blocks(t.reborrow(), |_| {}, |_| {});
        buf.get_out().copy_from_slice(&block[..n]);
    }
}

// note: unfortunately currently we can not write blanket impls of
// `BlockEncryptMut` and `BlockDecryptMut` for `StreamCipherCore`

/// Counter type usable with [`StreamCipherCore`].
pub trait Counter:
    TryFrom<i32>
    + TryFrom<u32>
    + TryFrom<u64>
    + TryFrom<u128>
    + TryFrom<usize>
    + TryInto<i32>
    + TryInto<u32>
    + TryInto<u64>
    + TryInto<u128>
    + TryInto<usize>
{
}

/// Block-level seeking trait for stream ciphers.
pub trait StreamCipherSeekCore: StreamCipherCore {
    /// Counter type used inside stream cipher.
    type Counter: Counter;

    /// Get current block position.
    fn get_block_pos(&self) -> Self::Counter;

    /// Set block position.
    fn set_block_pos(&mut self, pos: Self::Counter);
}

macro_rules! impl_counter {
    {$($t:ty )*} => {
        $( impl Counter for $t { } )*
    };
}

impl_counter! { u32 u64 u128 }
