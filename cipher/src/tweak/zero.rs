use core::marker::PhantomData;

use crypto_common::{array::ArraySize, Block, BlockSizes, ParBlocks, ParBlocksSizeUser};

use super::{
    TweakBlockCipherDecBackend, TweakBlockCipherDecClosure, TweakBlockCipherDecrypt,
    TweakBlockCipherEncBackend, TweakBlockCipherEncrypt, TweakSizeUser,
};
use crate::{
    tweak::TweakBlockCipherEncClosure, BlockCipherDecBackend, BlockCipherDecClosure,
    BlockCipherDecrypt, BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt,
    BlockSizeUser,
};

/// Wrapper around tweakable block cipher which implements
/// the [common block cipher traits][crate::block] using zero tweak.
#[derive(Debug, Clone)]
pub struct ZeroTweak<C: TweakSizeUser + BlockSizeUser>(pub C);

impl<C: TweakSizeUser + BlockSizeUser> BlockSizeUser for ZeroTweak<C> {
    type BlockSize = C::BlockSize;
}

impl<C: TweakBlockCipherEncrypt> BlockCipherEncrypt for ZeroTweak<C> {
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
        self.0.encrypt_with_backend(ClosureWrapper {
            f,
            _pd: PhantomData,
        });
    }
}

impl<C: TweakBlockCipherDecrypt> BlockCipherDecrypt for ZeroTweak<C> {
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
        self.0.decrypt_with_backend(ClosureWrapper {
            f,
            _pd: PhantomData,
        });
    }
}

/// Wrapper around non-tweakble block cipher closures which implements the tweakable
/// block cipher closure traits using zero tweak.
struct ClosureWrapper<TS: ArraySize, BS: BlockSizes, F> {
    f: F,
    _pd: PhantomData<(TS, BS)>,
}

impl<TS: ArraySize, BS: BlockSizes, F> BlockSizeUser for ClosureWrapper<TS, BS, F> {
    type BlockSize = BS;
}

impl<TS: ArraySize, BS: BlockSizes, F> TweakSizeUser for ClosureWrapper<TS, BS, F> {
    type TweakSize = TS;
}

impl<TS: ArraySize, BS: BlockSizes, F> TweakBlockCipherEncClosure for ClosureWrapper<TS, BS, F>
where
    F: BlockCipherEncClosure<BlockSize = BS>,
{
    fn call<B: TweakBlockCipherEncBackend<BlockSize = BS, TweakSize = TS>>(self, backend: &B) {
        self.f.call(&BackendWrapper {
            backend,
            _pd: PhantomData,
        })
    }
}

impl<TS: ArraySize, BS: BlockSizes, F> TweakBlockCipherDecClosure for ClosureWrapper<TS, BS, F>
where
    F: BlockCipherDecClosure<BlockSize = BS>,
{
    fn call<B: TweakBlockCipherDecBackend<BlockSize = BS, TweakSize = TS>>(self, backend: &B) {
        self.f.call(&BackendWrapper {
            backend,
            _pd: PhantomData,
        })
    }
}

/// Wrapper around tweakable block cipher backend which implements non-tweakable
/// block cipher backend traits using zero tweak.
struct BackendWrapper<'a, BS: BlockSizes, B> {
    backend: &'a B,
    _pd: PhantomData<BS>,
}

impl<BS: BlockSizes, B> BlockSizeUser for BackendWrapper<'_, BS, B> {
    type BlockSize = BS;
}

impl<BS: BlockSizes, B: ParBlocksSizeUser> ParBlocksSizeUser for BackendWrapper<'_, BS, B> {
    type ParBlocksSize = B::ParBlocksSize;
}

impl<BS: BlockSizes, B: TweakBlockCipherEncBackend<BlockSize = BS>> BlockCipherEncBackend
    for BackendWrapper<'_, BS, B>
{
    #[inline]
    fn encrypt_block(&self, block: inout::InOut<'_, '_, Block<Self>>) {
        self.backend.encrypt_block(&Default::default(), block);
    }

    #[inline]
    fn encrypt_par_blocks(&self, blocks: inout::InOut<'_, '_, ParBlocks<Self>>) {
        self.backend.encrypt_par_blocks(&Default::default(), blocks);
    }
}

impl<BS: BlockSizes, B: TweakBlockCipherDecBackend<BlockSize = BS>> BlockCipherDecBackend
    for BackendWrapper<'_, BS, B>
{
    #[inline]
    fn decrypt_block(&self, block: inout::InOut<'_, '_, Block<Self>>) {
        self.backend.decrypt_block(&Default::default(), block);
    }

    #[inline]
    fn decrypt_par_blocks(&self, blocks: inout::InOut<'_, '_, ParBlocks<Self>>) {
        self.backend.decrypt_par_blocks(&Default::default(), blocks);
    }
}
