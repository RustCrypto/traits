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

#[cfg(all(feature = "block-padding", feature = "alloc"))]
use alloc::{vec, vec::Vec};
use crypto_common::{Block, BlockSizeUser};
use inout::{InOut, InOutBuf, NotEqualError};
#[cfg(feature = "block-padding")]
use inout::{
    InOutBufReserved, PadError,
    block_padding::{self, Padding},
};

mod backends;
mod ctx;

use ctx::{BlockCtx, BlocksCtx};

pub use backends::{
    BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherEncBackend, BlockCipherEncClosure,
    BlockModeDecBackend, BlockModeDecClosure, BlockModeEncBackend, BlockModeEncClosure,
};

/// Encrypt-only functionality for block ciphers.
pub trait BlockCipherEncrypt: BlockSizeUser + Sized {
    /// Encrypt data using backend provided to the rank-2 closure.
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>);

    /// Encrypt single `inout` block.
    #[inline]
    fn encrypt_block_inout(&self, block: InOut<'_, '_, Block<Self>>) {
        self.encrypt_with_backend(BlockCtx { block });
    }

    /// Encrypt `inout` blocks.
    #[inline]
    fn encrypt_blocks_inout(&self, blocks: InOutBuf<'_, '_, Block<Self>>) {
        self.encrypt_with_backend(BlocksCtx { blocks });
    }

    /// Encrypt single block in-place.
    #[inline]
    fn encrypt_block(&self, block: &mut Block<Self>) {
        let block = block.into();
        self.encrypt_with_backend(BlockCtx { block });
    }

    /// Encrypt `in_block` and write result to `out_block`.
    #[inline]
    fn encrypt_block_b2b(&self, in_block: &Block<Self>, out_block: &mut Block<Self>) {
        let block = (in_block, out_block).into();
        self.encrypt_with_backend(BlockCtx { block });
    }

    /// Encrypt blocks in-place.
    #[inline]
    fn encrypt_blocks(&self, blocks: &mut [Block<Self>]) {
        let blocks = blocks.into();
        self.encrypt_with_backend(BlocksCtx { blocks });
    }

    /// Encrypt blocks buffer-to-buffer.
    ///
    /// Returns [`NotEqualError`] if provided `in_blocks` and `out_blocks`
    /// have different lengths.
    #[inline]
    fn encrypt_blocks_b2b(
        &self,
        in_blocks: &[Block<Self>],
        out_blocks: &mut [Block<Self>],
    ) -> Result<(), NotEqualError> {
        InOutBuf::new(in_blocks, out_blocks)
            .map(|blocks| self.encrypt_with_backend(BlocksCtx { blocks }))
    }

    /// Pad input and encrypt. Returns resulting ciphertext slice.
    ///
    /// Returns [`PadError`] if length of output buffer is not sufficient.
    #[cfg(feature = "block-padding")]
    #[inline]
    fn encrypt_padded_inout<'out, P: Padding>(
        &self,
        data: InOutBufReserved<'_, 'out, u8>,
    ) -> Result<&'out [u8], PadError> {
        let mut buf = data.into_padded_blocks::<P, Self::BlockSize>()?;
        self.encrypt_blocks_inout(buf.get_blocks());
        if let Some(block) = buf.get_tail_block() {
            self.encrypt_block_inout(block);
        }
        Ok(buf.into_out())
    }

    /// Pad input and encrypt in-place. Returns resulting ciphertext slice.
    ///
    /// Returns [`PadError`] if length of output buffer is not sufficient.
    #[cfg(feature = "block-padding")]
    #[inline]
    fn encrypt_padded<'a, P: Padding>(
        &self,
        buf: &'a mut [u8],
        msg_len: usize,
    ) -> Result<&'a [u8], PadError> {
        let buf = InOutBufReserved::from_mut_slice(buf, msg_len).map_err(|_| PadError)?;
        self.encrypt_padded_inout::<P>(buf)
    }

    /// Pad input and encrypt buffer-to-buffer. Returns resulting ciphertext slice.
    ///
    /// Returns [`PadError`] if length of output buffer is not sufficient.
    #[cfg(feature = "block-padding")]
    #[inline]
    fn encrypt_padded_b2b<'a, P: Padding>(
        &self,
        msg: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], PadError> {
        let buf = InOutBufReserved::from_slices(msg, out_buf).map_err(|_| PadError)?;
        self.encrypt_padded_inout::<P>(buf)
    }

    /// Pad `msg` with padding algorithm `P`, encrypt it into a newly allocated `Vec`,
    /// and return the resulting ciphertext vector.
    ///
    /// # Panics
    /// If `NoPadding` is used with a message size that is not a multiple of the cipher block size.
    #[cfg(all(feature = "block-padding", feature = "alloc"))]
    #[inline]
    fn encrypt_padded_vec<P: Padding>(&self, msg: &[u8]) -> Vec<u8> {
        use block_padding::{NoPadding, ZeroPadding};
        use core::any::TypeId;
        use crypto_common::typenum::Unsigned;

        let bs = Self::BlockSize::USIZE;
        let msg_len = msg.len();

        let pad_type_id = TypeId::of::<P>();
        let buf_blocks_len = if pad_type_id == TypeId::of::<NoPadding>() {
            if msg_len % bs != 0 {
                panic!(
                    "NoPadding is used with a {msg_len}‑byte message,
                    which is not a multiple of the {bs}‑byte cipher block size"
                );
            }
            msg_len / bs
        } else if pad_type_id == TypeId::of::<ZeroPadding>() {
            msg_len.div_ceil(bs)
        } else {
            1 + msg_len / bs
        };

        let mut buf = vec![0; bs * buf_blocks_len];
        let res_len = self
            .encrypt_padded_b2b::<P>(msg, &mut buf)
            .expect("`buf` has enough space for encryption")
            .len();
        buf.truncate(res_len);
        buf
    }
}

/// Decrypt-only functionality for block ciphers.
pub trait BlockCipherDecrypt: BlockSizeUser {
    /// Decrypt data using backend provided to the rank-2 closure.
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>);

    /// Decrypt single `inout` block.
    #[inline]
    fn decrypt_block_inout(&self, block: InOut<'_, '_, Block<Self>>) {
        self.decrypt_with_backend(BlockCtx { block });
    }

    /// Decrypt `inout` blocks.
    #[inline]
    fn decrypt_blocks_inout(&self, blocks: InOutBuf<'_, '_, Block<Self>>) {
        self.decrypt_with_backend(BlocksCtx { blocks });
    }

    /// Decrypt single block in-place.
    #[inline]
    fn decrypt_block(&self, block: &mut Block<Self>) {
        let block = block.into();
        self.decrypt_with_backend(BlockCtx { block });
    }

    /// Decrypt `in_block` and write result to `out_block`.
    #[inline]
    fn decrypt_block_b2b(&self, in_block: &Block<Self>, out_block: &mut Block<Self>) {
        let block = (in_block, out_block).into();
        self.decrypt_with_backend(BlockCtx { block });
    }

    /// Decrypt blocks in-place.
    #[inline]
    fn decrypt_blocks(&self, blocks: &mut [Block<Self>]) {
        let blocks = blocks.into();
        self.decrypt_with_backend(BlocksCtx { blocks });
    }

    /// Decrypt blocks buffer-to-buffer.
    ///
    /// Returns [`NotEqualError`] if provided `in_blocks` and `out_blocks`
    /// have different lengths.
    #[inline]
    fn decrypt_blocks_b2b(
        &self,
        in_blocks: &[Block<Self>],
        out_blocks: &mut [Block<Self>],
    ) -> Result<(), NotEqualError> {
        InOutBuf::new(in_blocks, out_blocks)
            .map(|blocks| self.decrypt_with_backend(BlocksCtx { blocks }))
    }

    /// Decrypt input and unpad it. Returns resulting plaintext slice.
    ///
    /// Returns [`block_padding::Error`] if padding is malformed or if input length is
    /// not multiple of `Self::BlockSize`.
    #[cfg(feature = "block-padding")]
    #[inline]
    fn decrypt_padded_inout<'out, P: Padding>(
        &self,
        data: InOutBuf<'_, 'out, u8>,
    ) -> Result<&'out [u8], block_padding::Error> {
        let (mut blocks, tail) = data.into_chunks();
        if !tail.is_empty() {
            return Err(block_padding::Error);
        }
        self.decrypt_blocks_inout(blocks.reborrow());
        P::unpad_blocks::<Self::BlockSize>(blocks.into_out())
    }

    /// Decrypt input and unpad it in-place. Returns resulting plaintext slice.
    ///
    /// Returns [`block_padding::Error`] if padding is malformed or if input length is
    /// not multiple of `Self::BlockSize`.
    #[cfg(feature = "block-padding")]
    #[inline]
    fn decrypt_padded<'a, P: Padding>(
        &self,
        buf: &'a mut [u8],
    ) -> Result<&'a [u8], block_padding::Error> {
        self.decrypt_padded_inout::<P>(buf.into())
    }

    /// Decrypt input and unpad it buffer-to-buffer. Returns resulting
    /// plaintext slice.
    ///
    /// Returns [`block_padding::Error`] if padding is malformed or if input length is
    /// not multiple of `Self::BlockSize`.
    #[cfg(feature = "block-padding")]
    #[inline]
    fn decrypt_padded_b2b<'a, P: Padding>(
        &self,
        in_buf: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], block_padding::Error> {
        if out_buf.len() < in_buf.len() {
            return Err(block_padding::Error);
        }
        let n = in_buf.len();
        // note: `new` always returns `Ok` here
        let buf = InOutBuf::new(in_buf, &mut out_buf[..n]).map_err(|_| block_padding::Error)?;
        self.decrypt_padded_inout::<P>(buf)
    }

    /// Decrypt input and unpad it in a newly allocated Vec. Returns resulting
    /// plaintext `Vec`.
    ///
    /// Returns [`block_padding::Error`] if padding is malformed or if input length is
    /// not multiple of `Self::BlockSize`.
    #[cfg(all(feature = "block-padding", feature = "alloc"))]
    #[inline]
    fn decrypt_padded_vec<P: Padding>(&self, buf: &[u8]) -> Result<Vec<u8>, block_padding::Error> {
        let mut out = vec![0; buf.len()];
        let len = self.decrypt_padded_b2b::<P>(buf, &mut out)?.len();
        out.truncate(len);
        Ok(out)
    }
}

impl<Alg: BlockCipherEncrypt> BlockCipherEncrypt for &Alg {
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
        Alg::encrypt_with_backend(self, f);
    }
}

impl<Alg: BlockCipherDecrypt> BlockCipherDecrypt for &Alg {
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
        Alg::decrypt_with_backend(self, f);
    }
}

/// Encrypt-only functionality for block ciphers and modes with mutable access to `self`.
///
/// The main use case for this trait is blocks modes, but it also can be used
/// for hardware cryptographic engines which require `&mut self` access to an
/// underlying hardware peripheral.
pub trait BlockModeEncrypt: BlockSizeUser + Sized {
    /// Encrypt data using backend provided to the rank-2 closure.
    fn encrypt_with_backend(&mut self, f: impl BlockModeEncClosure<BlockSize = Self::BlockSize>);

    /// Encrypt single `inout` block.
    #[inline]
    fn encrypt_block_inout(&mut self, block: InOut<'_, '_, Block<Self>>) {
        self.encrypt_with_backend(BlockCtx { block });
    }

    /// Encrypt `inout` blocks.
    #[inline]
    fn encrypt_blocks_inout(&mut self, blocks: InOutBuf<'_, '_, Block<Self>>) {
        self.encrypt_with_backend(BlocksCtx { blocks });
    }

    /// Encrypt single block in-place.
    #[inline]
    fn encrypt_block(&mut self, block: &mut Block<Self>) {
        let block = block.into();
        self.encrypt_with_backend(BlockCtx { block });
    }

    /// Encrypt `in_block` and write result to `out_block`.
    #[inline]
    fn encrypt_block_b2b(&mut self, in_block: &Block<Self>, out_block: &mut Block<Self>) {
        let block = (in_block, out_block).into();
        self.encrypt_with_backend(BlockCtx { block });
    }

    /// Encrypt blocks in-place.
    #[inline]
    fn encrypt_blocks(&mut self, blocks: &mut [Block<Self>]) {
        let blocks = blocks.into();
        self.encrypt_with_backend(BlocksCtx { blocks });
    }

    /// Encrypt blocks buffer-to-buffer.
    ///
    /// Returns [`NotEqualError`] if provided `in_blocks` and `out_blocks`
    /// have different lengths.
    #[inline]
    fn encrypt_blocks_b2b(
        &mut self,
        in_blocks: &[Block<Self>],
        out_blocks: &mut [Block<Self>],
    ) -> Result<(), NotEqualError> {
        InOutBuf::new(in_blocks, out_blocks)
            .map(|blocks| self.encrypt_with_backend(BlocksCtx { blocks }))
    }

    /// Pad input and encrypt. Returns resulting ciphertext slice.
    ///
    /// Returns [`PadError`] if length of output buffer is not sufficient.
    #[cfg(feature = "block-padding")]
    #[inline]
    fn encrypt_padded_inout<'out, P: Padding>(
        mut self,
        data: InOutBufReserved<'_, 'out, u8>,
    ) -> Result<&'out [u8], PadError> {
        let mut buf = data.into_padded_blocks::<P, Self::BlockSize>()?;
        self.encrypt_blocks_inout(buf.get_blocks());
        if let Some(block) = buf.get_tail_block() {
            self.encrypt_block_inout(block);
        }
        Ok(buf.into_out())
    }

    /// Pad input and encrypt in-place. Returns resulting ciphertext slice.
    ///
    /// Returns [`PadError`] if length of output buffer is not sufficient.
    #[cfg(feature = "block-padding")]
    #[inline]
    fn encrypt_padded<P: Padding>(self, buf: &mut [u8], msg_len: usize) -> Result<&[u8], PadError> {
        let buf = InOutBufReserved::from_mut_slice(buf, msg_len).map_err(|_| PadError)?;
        self.encrypt_padded_inout::<P>(buf)
    }

    /// Pad input and encrypt buffer-to-buffer. Returns resulting ciphertext slice.
    ///
    /// Returns [`PadError`] if length of output buffer is not sufficient.
    #[cfg(feature = "block-padding")]
    #[inline]
    fn encrypt_padded_b2b<'a, P: Padding>(
        self,
        msg: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], PadError> {
        let buf = InOutBufReserved::from_slices(msg, out_buf).map_err(|_| PadError)?;
        self.encrypt_padded_inout::<P>(buf)
    }

    /// Pad `msg` with padding algorithm `P`, encrypt it into a newly allocated `Vec`,
    /// and return the resulting ciphertext vector.
    ///
    /// # Panics
    /// If `NoPadding` is used with a message size that is not a multiple of the cipher block size.
    #[cfg(all(feature = "block-padding", feature = "alloc"))]
    #[inline]
    fn encrypt_padded_vec<P: Padding>(self, msg: &[u8]) -> Vec<u8> {
        use block_padding::{NoPadding, ZeroPadding};
        use core::any::TypeId;
        use crypto_common::typenum::Unsigned;

        let bs = Self::BlockSize::USIZE;
        let msg_len = msg.len();

        let pad_type_id = TypeId::of::<P>();
        let buf_blocks_len = if pad_type_id == TypeId::of::<NoPadding>() {
            if msg_len % bs != 0 {
                panic!(
                    "NoPadding is used with a {msg_len}‑byte message,
                    which is not a multiple of the {bs}‑byte cipher block size"
                );
            }
            msg_len / bs
        } else if pad_type_id == TypeId::of::<ZeroPadding>() {
            msg_len.div_ceil(bs)
        } else {
            1 + msg_len / bs
        };

        let mut buf = vec![0; bs * buf_blocks_len];
        let res_len = self
            .encrypt_padded_b2b::<P>(msg, &mut buf)
            .expect("`buf` has enough space for encryption")
            .len();
        buf.truncate(res_len);
        buf
    }
}

/// Decrypt-only functionality for block ciphers and modes with mutable access to `self`.
///
/// The main use case for this trait is blocks modes, but it also can be used
/// for hardware cryptographic engines which require `&mut self` access to an
/// underlying hardware peripheral.
pub trait BlockModeDecrypt: BlockSizeUser + Sized {
    /// Decrypt data using backend provided to the rank-2 closure.
    fn decrypt_with_backend(&mut self, f: impl BlockModeDecClosure<BlockSize = Self::BlockSize>);

    /// Decrypt single `inout` block.
    #[inline]
    fn decrypt_block_inout(&mut self, block: InOut<'_, '_, Block<Self>>) {
        self.decrypt_with_backend(BlockCtx { block });
    }

    /// Decrypt `inout` blocks.
    #[inline]
    fn decrypt_blocks_inout(&mut self, blocks: InOutBuf<'_, '_, Block<Self>>) {
        self.decrypt_with_backend(BlocksCtx { blocks });
    }

    /// Decrypt single block in-place.
    #[inline]
    fn decrypt_block(&mut self, block: &mut Block<Self>) {
        let block = block.into();
        self.decrypt_with_backend(BlockCtx { block });
    }

    /// Decrypt `in_block` and write result to `out_block`.
    #[inline]
    fn decrypt_block_b2b(&mut self, in_block: &Block<Self>, out_block: &mut Block<Self>) {
        let block = (in_block, out_block).into();
        self.decrypt_with_backend(BlockCtx { block });
    }

    /// Decrypt blocks in-place.
    #[inline]
    fn decrypt_blocks(&mut self, blocks: &mut [Block<Self>]) {
        let blocks = blocks.into();
        self.decrypt_with_backend(BlocksCtx { blocks });
    }

    /// Decrypt blocks buffer-to-buffer.
    ///
    /// Returns [`NotEqualError`] if provided `in_blocks` and `out_blocks`
    /// have different lengths.
    #[inline]
    fn decrypt_blocks_b2b(
        &mut self,
        in_blocks: &[Block<Self>],
        out_blocks: &mut [Block<Self>],
    ) -> Result<(), NotEqualError> {
        InOutBuf::new(in_blocks, out_blocks)
            .map(|blocks| self.decrypt_with_backend(BlocksCtx { blocks }))
    }

    /// Decrypt input and unpad it. Returns resulting plaintext slice.
    ///
    /// Returns [`block_padding::Error`] if padding is malformed or if input length is
    /// not multiple of `Self::BlockSize`.
    #[cfg(feature = "block-padding")]
    #[inline]
    fn decrypt_padded_inout<'out, P: Padding>(
        mut self,
        data: InOutBuf<'_, 'out, u8>,
    ) -> Result<&'out [u8], block_padding::Error> {
        let (mut blocks, tail) = data.into_chunks();
        if !tail.is_empty() {
            return Err(block_padding::Error);
        }
        self.decrypt_blocks_inout(blocks.reborrow());
        P::unpad_blocks::<Self::BlockSize>(blocks.into_out())
    }

    /// Decrypt input and unpad it in-place. Returns resulting plaintext slice.
    ///
    /// Returns [`block_padding::Error`] if padding is malformed or if input length is
    /// not multiple of `Self::BlockSize`.
    #[cfg(feature = "block-padding")]
    #[inline]
    fn decrypt_padded<P: Padding>(self, buf: &mut [u8]) -> Result<&[u8], block_padding::Error> {
        self.decrypt_padded_inout::<P>(buf.into())
    }

    /// Decrypt input and unpad it buffer-to-buffer. Returns resulting
    /// plaintext slice.
    ///
    /// Returns [`block_padding::Error`] if padding is malformed or if input length is
    /// not multiple of `Self::BlockSize`.
    #[cfg(feature = "block-padding")]
    #[inline]
    fn decrypt_padded_b2b<'a, P: Padding>(
        self,
        in_buf: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], block_padding::Error> {
        if out_buf.len() < in_buf.len() {
            return Err(block_padding::Error);
        }
        let n = in_buf.len();
        // note: `new` always returns `Ok` here
        let buf = InOutBuf::new(in_buf, &mut out_buf[..n]).map_err(|_| block_padding::Error)?;
        self.decrypt_padded_inout::<P>(buf)
    }

    /// Decrypt input and unpad it in a newly allocated Vec. Returns resulting
    /// plaintext `Vec`.
    ///
    /// Returns [`block_padding::Error`] if padding is malformed or if input length is
    /// not multiple of `Self::BlockSize`.
    #[cfg(all(feature = "block-padding", feature = "alloc"))]
    #[inline]
    fn decrypt_padded_vec<P: Padding>(self, buf: &[u8]) -> Result<Vec<u8>, block_padding::Error> {
        let mut out = vec![0; buf.len()];
        let len = self.decrypt_padded_b2b::<P>(buf, &mut out)?.len();
        out.truncate(len);
        Ok(out)
    }
}
