#![cfg(feature = "core-api")]

use digest::{
    HashMarker, Output, OutputSizeUser, Reset,
    consts::U8,
    core_api::{
        Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore, UpdateCore,
    },
};

/// Core of primitive XOR hasher for testing purposes
#[derive(Clone, Default, Debug)]
pub struct FixedHashCore {
    state: u64,
}

impl BlockSizeUser for FixedHashCore {
    type BlockSize = U8;
}

impl BufferKindUser for FixedHashCore {
    type BufferKind = block_buffer::Eager;
}

impl Reset for FixedHashCore {
    fn reset(&mut self) {
        self.state = 0;
    }
}

impl UpdateCore for FixedHashCore {
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        for block in blocks {
            self.state ^= u64::from_le_bytes(block.0)
        }
    }
}

impl HashMarker for FixedHashCore {}

impl OutputSizeUser for FixedHashCore {
    type OutputSize = U8;
}

impl FixedOutputCore for FixedHashCore {
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let block = buffer.pad_with_zeros();
        self.state ^= u64::from_le_bytes(block.0);
        out.copy_from_slice(&self.state.to_le_bytes());
    }
}

digest::newtype!(
    /// Primitive XOR hasher for testing purposes
    FixedHash(CoreWrapper<FixedHashCore>);
    delegate:
        Debug AlgorithmName
        Clone Default Reset
        BlockSizeUser OutputSizeUser HashMarker
        Update FixedOutput FixedOutputReset
);
