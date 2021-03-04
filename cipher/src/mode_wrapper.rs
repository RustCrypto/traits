//! Convinience wrapper around types which implement `BlockMode`.

use crate::errors::BlockModeError;
use crate::{BlockModeDecrypt, BlockModeEncrypt, FromBlockCipherNonce};
use block_buffer::{block_padding::Padding, BlockBuffer, LazyBlockBuffer};
use core::{marker::PhantomData, slice::from_mut};
use generic_array::{typenum::Unsigned, GenericArray};

/// Convinience wrapper around the [`BlockModeEncrypt`] trait, which handles
/// data buffering and provides slice-based methods.
pub struct BlockModeEncryptWrapper<M: BlockModeEncrypt, P: Padding<M::BlockSize>> {
    inner: M,
    buffer: BlockBuffer<M::BlockSize>,
    _p: PhantomData<P>,
}

impl<M, P> FromBlockCipherNonce for BlockModeEncryptWrapper<M, P>
where
    M: BlockModeEncrypt + FromBlockCipherNonce,
    P: Padding<M::BlockSize>,
{
    type BlockCipher = M::BlockCipher;
    type NonceSize = M::NonceSize;

    fn from_block_cipher_nonce(
        cipher: Self::BlockCipher,
        nonce: &GenericArray<u8, Self::NonceSize>,
    ) -> Self {
        Self {
            inner: M::from_block_cipher_nonce(cipher, nonce),
            buffer: Default::default(),
            _p: Default::default(),
        }
    }
}

impl<M, P> BlockModeEncryptWrapper<M, P>
where
    M: BlockModeEncrypt,
    P: Padding<M::BlockSize>,
{
    /// Encrypt part of a plaintext.
    ///
    /// This mehthod MUST be used in conjuction with the [`encrypt_final`][Self::encrypt_final] method,
    /// otherwise plaintext will not be properly padded and may be truncated.
    ///
    /// The method encrypts plaintext in `data`, writes the resulting plaintext
    /// into `out_buf`, and returns it in the `Ok` variant. If a whole message
    /// can not be processed, it caches plaintext leftovers into inner buffer
    /// for future use.
    ///
    /// It's recommended for `out_buf` to be at least one block longer than
    /// `data`, otherwise the method can return `Err(BlockModeError)` if there is
    /// not enough space for encrypted blocks.
    #[inline]
    pub fn encrypt_part<'a>(
        &mut self,
        plaintext: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], BlockModeError> {
        let Self { inner, buffer, .. } = self;
        buffer
            .block_mode_processing(plaintext, out_buf, |blocks| inner.encrypt_blocks(blocks))
            .map_err(|_| BlockModeError)
    }

    /// Pad and encrypt plaintext.
    ///
    /// The method pads `plaintext` and encrypts it writing the resulting
    /// ciphertext into `out_buf`.
    ///
    /// It's recommended for `out_buf` to be at least one block longer than
    /// `data`, otherwise the method can return `Err(BlockModeError)` if there is
    /// not enough space for encrypted blocks.
    #[inline]
    pub fn encrypt_final<'a>(
        mut self,
        plaintext: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], BlockModeError> {
        let Self { inner, buffer, .. } = &mut self;
        let res_len = buffer
            .block_mode_processing(plaintext, out_buf, |blocks| inner.encrypt_blocks(blocks))
            .map_err(|_| BlockModeError)?
            .len();
        let final_block = buffer.pad_with::<P>();
        inner.encrypt_blocks(from_mut(final_block));

        let bs = M::BlockSize::USIZE;
        let final_len = res_len.checked_add(bs).ok_or(BlockModeError)?;
        let buf = out_buf.get_mut(..final_len).ok_or(BlockModeError)?;
        // note: even though `buf[t..]` and `buf[res_len..]` are guaranteed to be
        // equivalent, compiler generates a panic branch for the latter.
        let t = final_len - bs;
        debug_assert_eq!(t, res_len);
        buf[t..].copy_from_slice(final_block);
        Ok(buf)
    }
}

/// Convinience wrapper around the [`BlockModeDecrypt`] trait, which handles
/// data buffering and provides slice-based methods.
pub struct BlockModeDecryptWrapper<M: BlockModeDecrypt, P: Padding<M::BlockSize>> {
    inner: M,
    buffer: LazyBlockBuffer<M::BlockSize>,
    _p: PhantomData<P>,
}

impl<M, P> FromBlockCipherNonce for BlockModeDecryptWrapper<M, P>
where
    M: BlockModeDecrypt + FromBlockCipherNonce,
    P: Padding<M::BlockSize>,
{
    type BlockCipher = M::BlockCipher;
    type NonceSize = M::NonceSize;

    fn from_block_cipher_nonce(
        cipher: Self::BlockCipher,
        nonce: &GenericArray<u8, Self::NonceSize>,
    ) -> Self {
        Self {
            inner: M::from_block_cipher_nonce(cipher, nonce),
            buffer: Default::default(),
            _p: Default::default(),
        }
    }
}

impl<M, P> BlockModeDecryptWrapper<M, P>
where
    M: BlockModeDecrypt,
    P: Padding<M::BlockSize>,
{
    /// Decrypt part of a ciphertext.
    ///
    /// This mehthod MUST be used in conjuction with the [`decrypt_final`] method,
    /// otherwise plaintext will not be properly padded and may be truncated.
    ///
    /// The method decrypts `ciphertext`, writes the resulting plaintext
    /// into `out_buf`, and returns it in the `Ok` variant. If a whole message
    /// can not be processed, it caches ciphertext leftovers into inner buffer
    /// for future use.
    ///
    /// It's recommended for `out_buf` to be at least one block longer than
    /// `data`, otherwise the method can return `Err(BlockModeError)` if there is
    /// not enough space for encrypted blocks.
    ///
    /// [`decrypt_final`]: Self::decrypt_final
    #[inline]
    pub fn decrypt_part<'a>(
        &mut self,
        ciphertext: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], BlockModeError> {
        let Self { inner, buffer, .. } = self;
        buffer
            .block_mode_processing(ciphertext, out_buf, |blocks| inner.decrypt_blocks(blocks))
            .map_err(|_| BlockModeError)
    }

    /// Pad and decrypt plaintext.
    ///
    /// The method decrypts ciphertext, writes the resulting plaintext into
    /// into `out_buf`, and unpads it.
    ///
    /// It's recommended for `out_buf` to be at least one block longer than
    /// `data`, otherwise the method can return `Err(BlockModeError)` if there is
    /// not enough space for encrypted blocks.
    #[inline]
    pub fn decrypt_final<'a>(
        mut self,
        ciphertext: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], BlockModeError> {
        let Self { inner, buffer, .. } = &mut self;
        let res_len = buffer
            .block_mode_processing(ciphertext, out_buf, |blocks| inner.decrypt_blocks(blocks))
            .map_err(|_| BlockModeError)?
            .len();
        let final_block = buffer.get_full_block().ok_or(BlockModeError)?;
        inner.decrypt_blocks(from_mut(final_block));
        let tail = P::unpad(final_block).map_err(|_| BlockModeError)?;

        let tail_len = tail.len();
        let final_len = res_len.checked_add(tail_len).ok_or(BlockModeError)?;
        let buf = out_buf.get_mut(..final_len).ok_or(BlockModeError)?;
        // note: even though `buf[t..]` and `buf[res_len..]` are guaranteed to be
        // equivalent, compiler generates a panic branch for the latter.
        let t = final_len - tail_len;
        debug_assert_eq!(t, res_len);
        buf[t..].copy_from_slice(tail);
        Ok(buf)
    }
}
