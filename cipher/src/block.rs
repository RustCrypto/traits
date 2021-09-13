//! Traits used to define functionality of [block ciphers][1] and [modes of operation][2].
//!
//! # About block ciphers
//!
//! Block ciphers are keyed, deterministic permutations of a fixed-sized input
//! "block" providing a reversible transformation to/from an encrypted output.
//! They are one of the fundamental structural components of [symmetric cryptography][3].
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher
//! [2]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
//! [3]: https://en.wikipedia.org/wiki/Symmetric-key_algorithm

use block_buffer::inout::{InOut, InOutBuf, InSrc, InTmpOutBuf, NotEqualError};
use generic_array::typenum::U1;

pub use crypto_common::{Block, BlockSizeUser};

/// Marker trait for block ciphers.
pub trait BlockCipher: BlockSizeUser {}

/// Encrypt-only functionality for block ciphers.
pub trait BlockEncrypt: BlockSizeUser {
    /// Encrypt single `inout` block.
    fn encrypt_block_inout(&self, block: InOut<'_, Block<Self>>);

    /// Encrypt `inout` blocks with given pre and post hooks.
    fn encrypt_blocks_with_pre(
        &self,
        blocks: InOutBuf<'_, Block<Self>>,
        pre_fn: impl FnMut(InTmpOutBuf<'_, Block<Self>>) -> InSrc,
        post_fn: impl FnMut(InTmpOutBuf<'_, Block<Self>>),
    ) {
        blocks.process_chunks::<U1, _, _, _, _, _>(
            self,
            pre_fn,
            post_fn,
            |state, mut chunk| state.encrypt_block_inout(chunk.get(0)),
            |state, mut chunk| state.encrypt_block_inout(chunk.get(0)),
        )
    }

    /// Encrypt single block in-place.
    #[inline]
    fn encrypt_block(&self, block: &mut Block<Self>) {
        self.encrypt_block_inout(block.into())
    }

    /// Encrypt single block block-to-block, i.e. encrypt
    /// block from `in_block` and write result to `out_block`.
    #[inline]
    fn encrypt_block_b2b(&self, in_block: &Block<Self>, out_block: &mut Block<Self>) {
        self.encrypt_block_inout((in_block, out_block).into())
    }

    /// Encrypt `inout` blocks with given post hook.
    fn encrypt_blocks_inout(
        &self,
        blocks: InOutBuf<'_, Block<Self>>,
        post_fn: impl FnMut(InTmpOutBuf<'_, Block<Self>>),
    ) {
        self.encrypt_blocks_with_pre(blocks, |_| InSrc::In, post_fn)
    }

    /// Encrypt blocks in-place with given post hook.
    fn encrypt_blocks(&self, blocks: &mut [Block<Self>], mut post_fn: impl FnMut(&[Block<Self>])) {
        self.encrypt_blocks_with_pre(
            blocks.into(),
            |_| InSrc::In,
            |mut buf| {
                buf.copy_tmp2out();
                post_fn(buf.get_out());
            },
        )
    }

    /// Encrypt blocks buffer-to-buffer with given post hook.
    ///
    /// Returns [`NotEqualError`] if provided `in_blocks` and `out_blocks`
    /// have different lengths.
    fn encrypt_blocks_b2b(
        &self,
        in_blocks: &[Block<Self>],
        out_blocks: &mut [Block<Self>],
        mut post_fn: impl FnMut(&[Block<Self>]),
    ) -> Result<(), NotEqualError> {
        self.encrypt_blocks_with_pre(
            InOutBuf::new(in_blocks, out_blocks)?,
            |_| InSrc::In,
            |mut buf| {
                buf.copy_tmp2out();
                post_fn(buf.get_out());
            },
        );
        Ok(())
    }
}

/// Decrypt-only functionality for block ciphers.
pub trait BlockDecrypt: BlockSizeUser {
    /// Decrypt single `inout` block.
    fn decrypt_block_inout(&self, block: InOut<'_, Block<Self>>);

    /// Decrypt `inout` blocks with given pre and post hooks.
    fn decrypt_blocks_with_pre(
        &self,
        blocks: InOutBuf<'_, Block<Self>>,
        pre_fn: impl FnMut(InTmpOutBuf<'_, Block<Self>>) -> InSrc,
        post_fn: impl FnMut(InTmpOutBuf<'_, Block<Self>>),
    ) {
        blocks.process_chunks::<U1, _, _, _, _, _>(
            self,
            pre_fn,
            post_fn,
            |state, mut chunk| state.decrypt_block_inout(chunk.get(0)),
            |state, mut chunk| state.decrypt_block_inout(chunk.get(0)),
        )
    }

    /// Decrypt single block in-place.
    #[inline]
    fn decrypt_block(&self, block: &mut Block<Self>) {
        self.decrypt_block_inout(block.into())
    }

    /// Decrypt single block block-to-block, i.e. encrypt
    /// block from `in_block` and write result to `out_block`.
    #[inline]
    fn decrypt_block_b2b(&self, in_block: &Block<Self>, out_block: &mut Block<Self>) {
        self.decrypt_block_inout((in_block, out_block).into())
    }

    /// Decrypt `inout` blocks with given post hook.
    fn decrypt_blocks_inout(
        &self,
        blocks: InOutBuf<'_, Block<Self>>,
        post_fn: impl FnMut(InTmpOutBuf<'_, Block<Self>>),
    ) {
        self.decrypt_blocks_with_pre(blocks, |_| InSrc::In, post_fn)
    }

    /// Decrypt blocks in-place with given post hook.
    fn decrypt_blocks(&self, blocks: &mut [Block<Self>], mut post_fn: impl FnMut(&[Block<Self>])) {
        self.decrypt_blocks_with_pre(
            blocks.into(),
            |_| InSrc::In,
            |mut buf| {
                buf.copy_tmp2out();
                post_fn(buf.get_out());
            },
        )
    }

    /// Decrypt blocks buffer-to-buffer with given post hook.
    ///
    /// Returns [`NotEqualError`] if provided `in_blocks` and `out_blocks`
    /// have different lengths.
    fn decrypt_blocks_b2b(
        &self,
        in_blocks: &[Block<Self>],
        out_blocks: &mut [Block<Self>],
        mut post_fn: impl FnMut(&[Block<Self>]),
    ) -> Result<(), NotEqualError> {
        self.decrypt_blocks_with_pre(
            InOutBuf::new(in_blocks, out_blocks)?,
            |_| InSrc::In,
            |mut buf| {
                buf.copy_tmp2out();
                post_fn(buf.get_out());
            },
        );
        Ok(())
    }
}

/// Encrypt-only functionality for block ciphers and modes with mutable access to `self`.
///
/// The main use case for this trait is blocks modes, but it also can be used
/// for hardware cryptographic engines which require `&mut self` access to an
/// underlying hardware peripheral.
pub trait BlockEncryptMut: BlockSizeUser {
    /// Encrypt single `inout` block.
    fn encrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>);

    /// Encrypt `inout` blocks with given pre and post hooks.
    fn encrypt_blocks_with_pre_mut(
        &mut self,
        blocks: InOutBuf<'_, Block<Self>>,
        pre_fn: impl FnMut(InTmpOutBuf<'_, Block<Self>>) -> InSrc,
        post_fn: impl FnMut(InTmpOutBuf<'_, Block<Self>>),
    ) {
        blocks.process_chunks::<U1, _, _, _, _, _>(
            self,
            pre_fn,
            post_fn,
            |state, mut chunk| state.encrypt_block_inout_mut(chunk.get(0)),
            |state, mut chunk| state.encrypt_block_inout_mut(chunk.get(0)),
        )
    }

    /// Encrypt block in-place.
    #[inline]
    fn encrypt_block_mut(&mut self, block: &mut Block<Self>) {
        self.encrypt_block_inout_mut(block.into())
    }

    /// Encrypt single block block-to-block, i.e. encrypt
    /// block from `in_block` and write result to `out_block`.
    #[inline]
    fn encrypt_block_b2b_mut(&mut self, in_block: &Block<Self>, out_block: &mut Block<Self>) {
        self.encrypt_block_inout_mut((in_block, out_block).into())
    }

    /// Encrypt `inout` blocks with given post hook.
    fn encrypt_blocks_inout_mut(
        &mut self,
        blocks: InOutBuf<'_, Block<Self>>,
        post_fn: impl FnMut(InTmpOutBuf<'_, Block<Self>>),
    ) {
        self.encrypt_blocks_with_pre_mut(blocks, |_| InSrc::In, post_fn)
    }

    /// Encrypt blocks in-place with given post hook.
    fn encrypt_blocks_mut(
        &mut self,
        blocks: &mut [Block<Self>],
        mut post_fn: impl FnMut(&[Block<Self>]),
    ) {
        self.encrypt_blocks_with_pre_mut(
            blocks.into(),
            |_| InSrc::In,
            |mut buf| {
                buf.copy_tmp2out();
                post_fn(buf.get_out());
            },
        )
    }

    /// Encrypt blocks buffer-to-buffer with given post hook.
    ///
    /// Returns [`NotEqualError`] if provided `in_blocks` and `out_blocks`
    /// have different lengths.
    fn decrypt_blocks_b2b_mut(
        &mut self,
        in_blocks: &[Block<Self>],
        out_blocks: &mut [Block<Self>],
        mut post_fn: impl FnMut(&[Block<Self>]),
    ) -> Result<(), NotEqualError> {
        self.encrypt_blocks_with_pre_mut(
            InOutBuf::new(in_blocks, out_blocks)?,
            |_| InSrc::In,
            |mut buf| {
                buf.copy_tmp2out();
                post_fn(buf.get_out());
            },
        );
        Ok(())
    }
}

/// Decrypt-only functionality for block ciphers and modes with mutable access to `self`.
///
/// The main use case for this trait is blocks modes, but it also can be used
/// for hardware cryptographic engines which require `&mut self` access to an
/// underlying hardware peripheral.
pub trait BlockDecryptMut: BlockSizeUser {
    /// Decrypt single `inout` block.
    fn decrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>);

    /// Decrypt `inout` blocks with given pre and post hooks.
    fn decrypt_blocks_with_pre_mut(
        &mut self,
        blocks: InOutBuf<'_, Block<Self>>,
        pre_fn: impl FnMut(InTmpOutBuf<'_, Block<Self>>) -> InSrc,
        post_fn: impl FnMut(InTmpOutBuf<'_, Block<Self>>),
    ) {
        blocks.process_chunks::<U1, _, _, _, _, _>(
            self,
            pre_fn,
            post_fn,
            |state, mut chunk| state.decrypt_block_inout_mut(chunk.get(0)),
            |state, mut chunk| state.decrypt_block_inout_mut(chunk.get(0)),
        )
    }

    /// Decrypt single block in-place.
    #[inline]
    fn decrypt_block_mut(&mut self, block: &mut Block<Self>) {
        self.decrypt_block_inout_mut(block.into())
    }

    /// Decrypt single block block-to-block, i.e. encrypt
    /// block from `in_block` and write result to `out_block`.
    #[inline]
    fn decrypt_block_b2b_mut(&mut self, in_block: &Block<Self>, out_block: &mut Block<Self>) {
        self.decrypt_block_inout_mut((in_block, out_block).into())
    }

    /// Decrypt `inout` blocks with given post hook.
    fn decrypt_blocks_inout_mut(
        &mut self,
        blocks: InOutBuf<'_, Block<Self>>,
        post_fn: impl FnMut(InTmpOutBuf<'_, Block<Self>>),
    ) {
        self.decrypt_blocks_with_pre_mut(blocks, |_| InSrc::In, post_fn)
    }

    /// Decrypt blocks in-place with given post hook.
    fn decrypt_blocks_mut(
        &mut self,
        blocks: &mut [Block<Self>],
        mut post_fn: impl FnMut(&[Block<Self>]),
    ) {
        self.decrypt_blocks_with_pre_mut(
            blocks.into(),
            |_| InSrc::In,
            |mut buf| {
                buf.copy_tmp2out();
                post_fn(buf.get_out());
            },
        )
    }

    /// Decrypt blocks buffer-to-buffer with given post hook.
    ///
    /// Returns [`NotEqualError`] if provided `in_blocks` and `out_blocks`
    /// have different lengths.
    fn decrypt_blocks_b2b_mut(
        &mut self,
        in_blocks: &[Block<Self>],
        out_blocks: &mut [Block<Self>],
        mut post_fn: impl FnMut(&[Block<Self>]),
    ) -> Result<(), NotEqualError> {
        self.decrypt_blocks_with_pre_mut(
            InOutBuf::new(in_blocks, out_blocks)?,
            |_| InSrc::In,
            |mut buf| {
                buf.copy_tmp2out();
                post_fn(buf.get_out());
            },
        );
        Ok(())
    }
}

impl<Alg: BlockEncrypt> BlockEncryptMut for Alg {
    #[inline]
    fn encrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>) {
        self.encrypt_block_inout(block)
    }

    fn encrypt_blocks_with_pre_mut(
        &mut self,
        blocks: InOutBuf<'_, Block<Self>>,
        pre_fn: impl FnMut(InTmpOutBuf<'_, Block<Self>>) -> InSrc,
        post_fn: impl FnMut(InTmpOutBuf<'_, Block<Self>>),
    ) {
        self.encrypt_blocks_with_pre(blocks, pre_fn, post_fn)
    }
}

impl<Alg: BlockDecrypt> BlockDecryptMut for Alg {
    #[inline]
    fn decrypt_block_inout_mut(&mut self, block: InOut<'_, Block<Self>>) {
        self.decrypt_block_inout(block)
    }

    fn decrypt_blocks_with_pre_mut(
        &mut self,
        blocks: InOutBuf<'_, Block<Self>>,
        pre_fn: impl FnMut(InTmpOutBuf<'_, Block<Self>>) -> InSrc,
        post_fn: impl FnMut(InTmpOutBuf<'_, Block<Self>>),
    ) {
        self.decrypt_blocks_with_pre(blocks, pre_fn, post_fn)
    }
}

impl<Alg: BlockEncrypt> BlockEncrypt for &Alg {
    #[inline]
    fn encrypt_block_inout(&self, block: InOut<'_, Block<Self>>) {
        Alg::encrypt_block_inout(self, block)
    }

    fn encrypt_blocks_with_pre(
        &self,
        blocks: InOutBuf<'_, Block<Self>>,
        pre_fn: impl FnMut(InTmpOutBuf<'_, Block<Self>>) -> InSrc,
        post_fn: impl FnMut(InTmpOutBuf<'_, Block<Self>>),
    ) {
        Alg::encrypt_blocks_with_pre(self, blocks, pre_fn, post_fn)
    }
}

impl<Alg: BlockDecrypt> BlockDecrypt for &Alg {
    #[inline]
    fn decrypt_block_inout(&self, block: InOut<'_, Block<Self>>) {
        Alg::decrypt_block_inout(self, block)
    }

    fn decrypt_blocks_with_pre(
        &self,
        blocks: InOutBuf<'_, Block<Self>>,
        pre_fn: impl FnMut(InTmpOutBuf<'_, Block<Self>>) -> InSrc,
        post_fn: impl FnMut(InTmpOutBuf<'_, Block<Self>>),
    ) {
        Alg::decrypt_blocks_with_pre(self, blocks, pre_fn, post_fn)
    }
}
