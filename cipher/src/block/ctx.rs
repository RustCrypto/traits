use crypto_common::{typenum::Unsigned, Block, BlockSizeUser, BlockSizes};
use inout::{InOut, InOutBuf};

use super::{
    BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherEncBackend, BlockCipherEncClosure,
    BlockModeDecBackend, BlockModeDecClosure, BlockModeEncBackend, BlockModeEncClosure,
};

/// Closure used in methods which operate over separate blocks.
pub(super) struct BlockCtx<'inp, 'out, BS: BlockSizes> {
    pub block: InOut<'inp, 'out, Block<Self>>,
}

impl<'inp, 'out, BS: BlockSizes> BlockSizeUser for BlockCtx<'inp, 'out, BS> {
    type BlockSize = BS;
}

impl<'inp, 'out, BS: BlockSizes> BlockCipherEncClosure for BlockCtx<'inp, 'out, BS> {
    #[inline(always)]
    fn call<B: BlockCipherEncBackend<BlockSize = BS>>(self, backend: &B) {
        backend.encrypt_block(self.block);
    }
}

impl<'inp, 'out, BS: BlockSizes> BlockCipherDecClosure for BlockCtx<'inp, 'out, BS> {
    #[inline(always)]
    fn call<B: BlockCipherDecBackend<BlockSize = BS>>(self, backend: &B) {
        backend.decrypt_block(self.block);
    }
}

impl<'inp, 'out, BS: BlockSizes> BlockModeEncClosure for BlockCtx<'inp, 'out, BS> {
    #[inline(always)]
    fn call<B: BlockModeEncBackend<BlockSize = BS>>(self, backend: &mut B) {
        backend.encrypt_block(self.block);
    }
}

impl<'inp, 'out, BS: BlockSizes> BlockModeDecClosure for BlockCtx<'inp, 'out, BS> {
    #[inline(always)]
    fn call<B: BlockModeDecBackend<BlockSize = BS>>(self, backend: &mut B) {
        backend.decrypt_block(self.block);
    }
}
/// Closure used in methods which operate over slice of blocks.
pub(super) struct BlocksCtx<'inp, 'out, BS: BlockSizes> {
    pub blocks: InOutBuf<'inp, 'out, Block<Self>>,
}

impl<'inp, 'out, BS: BlockSizes> BlockSizeUser for BlocksCtx<'inp, 'out, BS> {
    type BlockSize = BS;
}

impl<'inp, 'out, BS: BlockSizes> BlockCipherEncClosure for BlocksCtx<'inp, 'out, BS> {
    #[inline(always)]
    fn call<B: BlockCipherEncBackend<BlockSize = BS>>(self, backend: &B) {
        if B::ParBlocksSize::USIZE > 1 {
            let (chunks, tail) = self.blocks.into_chunks();
            for chunk in chunks {
                backend.encrypt_par_blocks(chunk);
            }
            backend.encrypt_tail_blocks(tail);
        } else {
            for block in self.blocks {
                backend.encrypt_block(block);
            }
        }
    }
}

impl<'inp, 'out, BS: BlockSizes> BlockCipherDecClosure for BlocksCtx<'inp, 'out, BS> {
    #[inline(always)]
    fn call<B: BlockCipherDecBackend<BlockSize = BS>>(self, backend: &B) {
        if B::ParBlocksSize::USIZE > 1 {
            let (chunks, tail) = self.blocks.into_chunks();
            for chunk in chunks {
                backend.decrypt_par_blocks(chunk);
            }
            backend.decrypt_tail_blocks(tail);
        } else {
            for block in self.blocks {
                backend.decrypt_block(block);
            }
        }
    }
}

impl<'inp, 'out, BS: BlockSizes> BlockModeEncClosure for BlocksCtx<'inp, 'out, BS> {
    #[inline(always)]
    fn call<B: BlockModeEncBackend<BlockSize = BS>>(self, backend: &mut B) {
        if B::ParBlocksSize::USIZE > 1 {
            let (chunks, tail) = self.blocks.into_chunks();
            for chunk in chunks {
                backend.encrypt_par_blocks(chunk);
            }
            backend.encrypt_tail_blocks(tail);
        } else {
            for block in self.blocks {
                backend.encrypt_block(block);
            }
        }
    }
}

impl<'inp, 'out, BS: BlockSizes> BlockModeDecClosure for BlocksCtx<'inp, 'out, BS> {
    #[inline(always)]
    fn call<B: BlockModeDecBackend<BlockSize = BS>>(self, backend: &mut B) {
        if B::ParBlocksSize::USIZE > 1 {
            let (chunks, tail) = self.blocks.into_chunks();
            for chunk in chunks {
                backend.decrypt_par_blocks(chunk);
            }
            backend.decrypt_tail_blocks(tail);
        } else {
            for block in self.blocks {
                backend.decrypt_block(block);
            }
        }
    }
}
