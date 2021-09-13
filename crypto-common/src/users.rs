use block_buffer::DigestBuffer;
use generic_array::{
    typenum::{type_operators::IsLess, U256},
    ArrayLength, GenericArray,
};
#[cfg(feature = "rand_core")]
use rand_core::{CryptoRng, RngCore};

/// Block on which [`BlockUser`] implementors operate.
pub type Block<B> = GenericArray<u8, <B as BlockSizeUser>::BlockSize>;
/// Output array of [`OutputSizeUser`] implementors.
pub type Output<T> = GenericArray<u8, <T as OutputSizeUser>::OutputSize>;
/// Key used by [`KeyUser`] implementors.
pub type Key<B> = GenericArray<u8, <B as KeySizeUser>::KeySize>;
/// Initialization vector (nonce) used by [`IvUser`] implementors.
pub type Iv<B> = GenericArray<u8, <B as IvSizeUser>::IvSize>;

/// Types which process data in blocks.
pub trait BlockSizeUser {
    /// Size of the block in bytes.
    type BlockSize: ArrayLength<u8> + IsLess<U256> + 'static;
}

impl<T: BlockSizeUser> BlockSizeUser for &T {
    type BlockSize = T::BlockSize;
}

impl<T: BlockSizeUser> BlockSizeUser for &mut T {
    type BlockSize = T::BlockSize;
}

/// Types which return data with the given size.
pub trait OutputSizeUser {
    /// Size of the output in bytes.
    type OutputSize: ArrayLength<u8> + 'static;
}

/// Types which use key for initialization.
///
/// Generally it's used indirectly via [`KeyInit`] or [`KeyIvInit`].
pub trait KeySizeUser {
    /// Key size in bytes.
    type KeySize: ArrayLength<u8> + 'static;

    /// Generate random key using the provided [`CryptoRng`].
    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    #[inline]
    fn generate_key(mut rng: impl CryptoRng + RngCore) -> Key<Self> {
        let mut key = Key::<Self>::default();
        rng.fill_bytes(&mut key);
        key
    }
}

/// Types which use initialization vector (nonce) for initialization.
///
/// Generally it's used indirectly via [`KeyIvInit`] or [`InnerIvInit`].
pub trait IvSizeUser {
    /// Initialization vector size in bytes.
    type IvSize: ArrayLength<u8> + 'static;

    /// Generate random IV using the provided [`CryptoRng`].
    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    #[inline]
    fn generate_iv(mut rng: impl CryptoRng + RngCore) -> Iv<Self> {
        let mut iv = Iv::<Self>::default();
        rng.fill_bytes(&mut iv);
        iv
    }
}

/// Types which use another type for initialization.
///
/// Generally it's used indirectly via [`InnerInit`] or [`InnerIvInit`].
pub trait InnerUser {
    /// Inner type.
    type Inner;
}

/// Types which use [`DigestBuffer`] functionality.
pub trait BufferUser: BlockSizeUser {
    /// Block buffer type over which value operates.
    type Buffer: DigestBuffer<Self::BlockSize>;
}
