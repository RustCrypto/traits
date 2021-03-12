use crate::{BlockCipher, FromKeyNonce};
use generic_array::{ArrayLength, GenericArray};

/// Trait for types which implement a block cipher [mode of operation][1].
///
/// [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
pub trait BlockMode {
    /// Size of the block in bytes
    type BlockSize: ArrayLength<u8>;
}

/// Trait for a block cipher mode of operation block-level encryptor.
///
/// This trait operates only on blocks, for convinient slice-based methods with padding
/// see the [`BlockModeEncryptWrapper`][crate::BlockModeEncryptWrapper] type.
pub trait BlockModeEncrypt: BlockMode {
    /// Encrypt blocks of data.
    fn encrypt_blocks(&mut self, blocks: &mut [GenericArray<u8, Self::BlockSize>]);
}

/// Trait for a block cipher mode of operation block-level decryptor.
///
/// This trait operates only on blocks, for convinient slice-based methods with padding
/// see the [`BlockModeDecryptWrapper`][crate::BlockModeDecryptWrapper] type.
pub trait BlockModeDecrypt: BlockMode {
    /// Decrypt blocks of data.
    fn decrypt_blocks(&mut self, blocks: &mut [GenericArray<u8, Self::BlockSize>]);
}

/// Trait for a block mode, used to obtain the current state in the form of an IV
/// that can initialize a BlockMode later and resume the original operation.
///
/// The IV value SHOULD be used for resuming operations only and MUST NOT be
/// exposed to attackers. Failing to comply with this requirement breaks
/// unpredictability and opens attack venues (see e.g. [1], sec. 3.6.2).
///
/// [1]: https://www.cs.umd.edu/~jkatz/imc.html
pub trait BlockModeIvState<C: BlockCipher>: FromKeyNonce {
    /// Returns the IV needed to process the following block. This value MUST
    /// NOT be exposed to attackers.
    fn iv_state(&self) -> GenericArray<u8, Self::NonceSize>;
}
