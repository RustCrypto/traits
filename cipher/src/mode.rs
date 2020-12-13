use core::marker::PhantomData;
use block_padding::Padding;
use generic_array::{ArrayLength, GenericArray};

/// Block on which a [`BlockModeCore`] operates.
pub type Block<M> = GenericArray<u8, <M as BlockModeCore>::BlockSize>;

/// Core trait for a block cipher mode of operation.
pub trait BlockModeCore {
    /// Block size in bytes
    type BlockSize: ArrayLength<u8>;

    /// Encrypt blocks of data
    fn encrypt_blocks(&mut self, blocks: &mut [Block<Self>]);

    /// Decrypt blocks of data
    fn decrypt_blocks(&mut self, blocks: &mut [Block<Self>]);

    ///
    fn into_encryptor<>(self) -> BlockModeEncryptor<Self, P>
}

pub struct BlockModeEncryptor<M: BlockModeCore, P: Padding>{
    inner: M,
    p: PhantomData<P>,
}

/*
    /// Encrypt message in-place.
    ///
    /// `&buffer[..pos]` is used as a message and `&buffer[pos..]` as a reserved
    /// space for padding. The padding space should be big enough for padding,
    /// otherwise method will return `Err(BlockModeError)`.
    fn encrypt(mut self, buffer: &mut [u8], pos: usize) -> Result<&[u8], BlockModeError> {
        let bs = C::BlockSize::to_usize();
        let buf = P::pad(buffer, pos, bs).map_err(|_| BlockModeError)?;
        self.encrypt_blocks(to_blocks(buf));
        Ok(buf)
    }

    /// Decrypt message in-place.
    ///
    /// Returns an error if `buffer` length is not multiple of block size and
    /// if after decoding message has malformed padding.
    fn decrypt(mut self, buffer: &mut [u8]) -> Result<&[u8], BlockModeError> {
        let bs = C::BlockSize::to_usize();
        if buffer.len() % bs != 0 {
            return Err(BlockModeError);
        }
        self.decrypt_blocks(to_blocks(buffer));
        P::unpad(buffer).map_err(|_| BlockModeError)
    }

    /// Encrypt message and store result in vector.
    #[cfg(feature = "alloc")]
    fn encrypt_to_vec(mut self, plaintext: &[u8]) -> Vec<u8> {
        let bs = C::BlockSize::to_usize();
        let pos = plaintext.len();
        let n = pos + bs;
        let mut buf = Vec::with_capacity(n);
        buf.extend_from_slice(plaintext);
        // prepare space for padding
        let block: Block<C> = Default::default();
        buf.extend_from_slice(&block[..n - pos]);

        let n = P::pad(&mut buf, pos, bs)
            .expect("enough space for padding is allocated")
            .len();
        buf.truncate(n);
        self.encrypt_blocks(to_blocks(&mut buf));
        buf
    }

    /// Encrypt message and store result in vector.
    #[cfg(feature = "alloc")]
    fn decrypt_to_vec(mut self, ciphertext: &[u8]) -> Result<Vec<u8>, BlockModeError> {
        let bs = C::BlockSize::to_usize();
        if ciphertext.len() % bs != 0 {
            return Err(BlockModeError);
        }
        let mut buf = ciphertext.to_vec();
        self.decrypt_blocks(to_blocks(&mut buf));
        let n = P::unpad(&buf).map_err(|_| BlockModeError)?.len();
        buf.truncate(n);
        Ok(buf)
    }
*/