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
use crate::inout::{InOutBuf, InOutVal, InResOutBuf};
pub use crypto_common::{Block, BlockProcessing, InnerIvInit};
use generic_array::{typenum::U1, GenericArray};

/// Marker trait for types which represent block ciphers.
///
/// Even if a type is marked by this trait implements only `BlockEncryptMut` and/or
/// `BlockDecryptMut`, it is assumed that its inner state is not changed by calling
/// its methods, i.e. mutable-only implementations are used only for hardware
/// encryption engines which require `&mut self` access to an underlying hardware
///  peripheral.
pub trait BlockCipher {}

/// Marker trait for types which represent asynchronous stream ciphers.
pub trait AsyncStreamCipher {}

/// Encrypt-only functionality of block ciphers.
pub trait BlockEncrypt: BlockProcessing {
    /// Encrypt the provided block.
    ///
    /// Usually `block` is either `&mut Block`, or `(&Block, &mut Block)`.
    fn encrypt_block(&self, block: impl InOutVal<Block<Self>>);

    /// Encrypt provided blocks in parallel.
    fn encrypt_blocks(
        &self,
        mut blocks: InOutBuf<'_, '_, Block<Self>>,
        proc: impl FnMut(InResOutBuf<'_, '_, '_, Block<Self>>),
    ) {
        blocks.chunks::<U1, _, _, _, _>(
            &self,
            |state, inc, res| state.encrypt_block((&inc[0], &mut res[0])),
            |state, inc, res| state.encrypt_block((&inc[0], &mut res[0])),
            proc,
        );
    }
}

/// Decrypt-only functionality of block ciphers.
pub trait BlockDecrypt: BlockProcessing {
    /// Decrypt the provided block.
    ///
    /// Usually `block` is either `&mut Block`, or `(&Block, &mut Block)`.
    fn decrypt_block(&self, block: impl InOutVal<Block<Self>>);

    /// Decrypt provided blocks in parallel.
    fn decrypt_blocks(
        &self,
        mut blocks: InOutBuf<'_, '_, Block<Self>>,
        proc: impl FnMut(InResOutBuf<'_, '_, '_, Block<Self>>),
    ) {
        blocks.chunks::<U1, _, _, _, _>(
            &self,
            |state, inc, res| state.decrypt_block((&inc[0], &mut res[0])),
            |state, inc, res| state.decrypt_block((&inc[0], &mut res[0])),
            proc,
        );
    }
}

/// Encrypt-only functionality of block ciphers and block cipher modes of operation.
pub trait BlockEncryptMut: BlockProcessing {
    /// Encrypt the provided block.
    ///
    /// Usually `block` is either `&mut Block`, or `(&Block, &mut Block)`.
    fn encrypt_block(&mut self, block: impl InOutVal<Block<Self>>);

    /// Encrypt provided blocks in parallel.
    fn encrypt_blocks(
        &mut self,
        mut blocks: InOutBuf<'_, '_, Block<Self>>,
        proc: impl FnMut(InResOutBuf<'_, '_, '_, Block<Self>>),
    ) {
        blocks.chunks::<U1, _, _, _, _>(
            self,
            |state, inc, res| state.encrypt_block((&inc[0], &mut res[0])),
            |state, inc, res| state.encrypt_block((&inc[0], &mut res[0])),
            proc,
        );
    }
}

/// Decrypt-only functionality of block ciphers and block cipher modes of operation.
pub trait BlockDecryptMut: BlockProcessing {
    /// Decrypt the provided block.
    ///
    /// Usually `block` is either `&mut Block`, or `(&Block, &mut Block)`.
    fn decrypt_block(&mut self, block: impl InOutVal<Block<Self>>);

    /// Decrypt provided blocks in parallel.
    fn decrypt_blocks(
        &mut self,
        mut blocks: InOutBuf<'_, '_, Block<Self>>,
        proc: impl FnMut(InResOutBuf<'_, '_, '_, Block<Self>>),
    ) {
        blocks.chunks::<U1, _, _, _, _>(
            self,
            |state, inc, res| state.decrypt_block((&inc[0], &mut res[0])),
            |state, inc, res| state.decrypt_block((&inc[0], &mut res[0])),
            proc,
        );
    }
}

/// Trait for block cipher modes of operation, used to obtain the current state
/// in the form of an IV that can re-initialize mode later and resume the original
/// operation.
///
/// The IV value SHOULD be used for resuming operations only and MUST NOT be
/// exposed to attackers. Failing to comply with this requirement breaks
/// unpredictability and opens attack venues (see e.g. [1], sec. 3.6.2).
///
/// [1]: https://www.cs.umd.edu/~jkatz/imc.html
pub trait IvState: InnerIvInit {
    /// Returns the IV needed to process the following block. This value MUST
    /// NOT be exposed to attackers.
    fn iv_state(&self) -> GenericArray<u8, Self::IvSize>;
}

// =========================== BLANKET IMPLS ===========================

impl<T: BlockCipher> BlockCipher for &T {}

impl<T: BlockCipher> BlockCipher for &mut T {}

impl<Alg: BlockEncrypt> BlockEncrypt for &Alg {
    #[inline]
    fn encrypt_block(&self, block: impl InOutVal<Block<Self>>) {
        Alg::encrypt_block(self, block);
    }

    #[inline]
    fn encrypt_blocks(
        &self,
        blocks: InOutBuf<'_, '_, Block<Self>>,
        proc: impl FnMut(InResOutBuf<'_, '_, '_, Block<Self>>),
    ) {
        Alg::encrypt_blocks(self, blocks, proc);
    }
}

impl<Alg: BlockDecrypt> BlockDecrypt for &Alg {
    #[inline]
    fn decrypt_block(&self, block: impl InOutVal<Block<Self>>) {
        Alg::decrypt_block(self, block)
    }

    #[inline]
    fn decrypt_blocks(
        &self,
        blocks: InOutBuf<'_, '_, Block<Self>>,
        proc: impl FnMut(InResOutBuf<'_, '_, '_, Block<Self>>),
    ) {
        Alg::decrypt_blocks(self, blocks, proc);
    }
}

impl<Alg: BlockEncrypt> BlockEncryptMut for Alg {
    #[inline]
    fn encrypt_block(&mut self, block: impl InOutVal<Block<Self>>) {
        Alg::encrypt_block(self, block)
    }

    #[inline]
    fn encrypt_blocks(
        &mut self,
        blocks: InOutBuf<'_, '_, Block<Self>>,
        proc: impl FnMut(InResOutBuf<'_, '_, '_, Block<Self>>),
    ) {
        Alg::encrypt_blocks(self, blocks, proc);
    }
}

impl<Alg: BlockDecrypt> BlockDecryptMut for Alg {
    #[inline]
    fn decrypt_block(&mut self, block: impl InOutVal<Block<Self>>) {
        Alg::decrypt_block(self, block);
    }

    #[inline]
    fn decrypt_blocks(
        &mut self,
        blocks: InOutBuf<'_, '_, Block<Self>>,
        proc: impl FnMut(InResOutBuf<'_, '_, '_, Block<Self>>),
    ) {
        Alg::decrypt_blocks(self, blocks, proc);
    }
}

// note: unfortunately we can't write a blanket implementation of
// `BlockEncryptMut`/`BlockDecryptMut` for implementors of `StreamCipherCore`
// since such impl will conflict with blanket impls for
// `BlockEncrypt`/`BlockDecrypt`
