//! Common cryptographic traits.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, missing_debug_implementations)]

/// Hazardous materials.
pub mod hazmat;

/// Secure random generation.
#[cfg(feature = "rand_core")]
mod generate;

pub use hybrid_array as array;
pub use hybrid_array::typenum;

#[cfg(feature = "getrandom")]
pub use getrandom;
#[cfg(feature = "rand_core")]
pub use {generate::Generate, rand_core};

use core::fmt;
use hybrid_array::{
    Array, ArraySize,
    typenum::{Diff, Sum, Unsigned},
};

/// Block on which [`BlockSizeUser`] implementors operate.
pub type Block<B> = Array<u8, <B as BlockSizeUser>::BlockSize>;

/// Parallel blocks on which [`ParBlocksSizeUser`] implementors operate.
pub type ParBlocks<T> = Array<Block<T>, <T as ParBlocksSizeUser>::ParBlocksSize>;

/// Output array of [`OutputSizeUser`] implementors.
pub type Output<T> = Array<u8, OutputSize<T>>;

/// Alias for the output size of [`OutputSizeUser`] implementors.
pub type OutputSize<T> = <T as OutputSizeUser>::OutputSize;

/// Key used by [`KeySizeUser`] implementors.
pub type Key<B> = Array<u8, <B as KeySizeUser>::KeySize>;

/// Initialization vector (nonce) used by [`IvSizeUser`] implementors.
pub type Iv<B> = Array<u8, <B as IvSizeUser>::IvSize>;

/// Alias for `AddBlockSize<A, B> = Sum<T, B::BlockSize>`
pub type AddBlockSize<T, B> = Sum<T, <B as BlockSizeUser>::BlockSize>;

/// Alias for `SubBlockSize<A, B> = Diff<T, B::BlockSize>`
pub type SubBlockSize<T, B> = Diff<T, <B as BlockSizeUser>::BlockSize>;

/// Types which process data in blocks.
pub trait BlockSizeUser {
    /// Size of the block in bytes.
    type BlockSize: BlockSizes;

    /// Return block size in bytes.
    #[inline(always)]
    fn block_size() -> usize {
        Self::BlockSize::USIZE
    }
}

impl<T: BlockSizeUser> BlockSizeUser for &T {
    type BlockSize = T::BlockSize;
}

impl<T: BlockSizeUser> BlockSizeUser for &mut T {
    type BlockSize = T::BlockSize;
}

/// Trait implemented for supported block sizes, i.e. for types from `U1` to `U255`.
pub trait BlockSizes: ArraySize + sealed::BlockSizes {}

impl<T: ArraySize + sealed::BlockSizes> BlockSizes for T {}

mod sealed {
    use crate::typenum::{IsLess, NonZero, True, U256, Unsigned};

    pub trait BlockSizes {}

    impl<T: Unsigned> BlockSizes for T where Self: IsLess<U256, Output = True> + NonZero {}
}

/// Types which can process blocks in parallel.
pub trait ParBlocksSizeUser: BlockSizeUser {
    /// Number of blocks which can be processed in parallel.
    type ParBlocksSize: ArraySize;
}

/// Types which return data with the given size.
pub trait OutputSizeUser {
    /// Size of the output in bytes.
    type OutputSize: ArraySize;

    /// Return output size in bytes.
    #[inline(always)]
    fn output_size() -> usize {
        Self::OutputSize::USIZE
    }
}

/// Types which use key for initialization.
///
/// Generally it's used indirectly via [`KeyInit`] or [`KeyIvInit`].
pub trait KeySizeUser {
    /// Key size in bytes.
    type KeySize: ArraySize;

    /// Return key size in bytes.
    #[inline(always)]
    fn key_size() -> usize {
        Self::KeySize::USIZE
    }
}

/// Types which use initialization vector (nonce) for initialization.
///
/// Generally it's used indirectly via [`KeyIvInit`] or [`InnerIvInit`].
pub trait IvSizeUser {
    /// Initialization vector size in bytes.
    type IvSize: ArraySize;

    /// Return IV size in bytes.
    #[inline(always)]
    fn iv_size() -> usize {
        Self::IvSize::USIZE
    }
}

/// Types which use another type for initialization.
///
/// Generally it's used indirectly via [`InnerInit`] or [`InnerIvInit`].
pub trait InnerUser {
    /// Inner type.
    type Inner;
}

/// Resettable types.
pub trait Reset {
    /// Reset state to its initial value.
    fn reset(&mut self);
}

/// Trait which stores algorithm name constant, used in `Debug` implementations.
pub trait AlgorithmName {
    /// Write algorithm name into `f`.
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result;
}

/// Types which can be initialized from a key.
pub trait KeyInit: KeySizeUser + Sized {
    /// Create new value from fixed size key.
    fn new(key: &Key<Self>) -> Self;

    /// Check if the key might be considered weak.
    #[inline]
    fn weak_key_test(_key: &Key<Self>) -> Result<(), WeakKeyError> {
        Ok(())
    }

    /// Create new value from fixed size key after checking it for weakness.
    #[inline]
    fn new_checked(key: &Key<Self>) -> Result<Self, WeakKeyError> {
        Self::weak_key_test(key)?;
        Ok(Self::new(key))
    }

    /// Create new value from variable size key.
    #[inline]
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        <&Key<Self>>::try_from(key)
            .map(Self::new)
            .map_err(|_| InvalidLength)
    }
}

/// Types which can be initialized from a key and initialization vector (nonce).
pub trait KeyIvInit: KeySizeUser + IvSizeUser + Sized {
    /// Create new value from fixed length key and nonce.
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self;

    /// Check if the key might be considered weak.
    #[inline]
    fn weak_key_test(_key: &Key<Self>) -> Result<(), WeakKeyError> {
        Ok(())
    }

    /// Create new value from fixed length key and nonce after checking the key for weakness.
    #[inline]
    fn new_checked(key: &Key<Self>, iv: &Iv<Self>) -> Result<Self, WeakKeyError> {
        Self::weak_key_test(key)?;
        Ok(Self::new(key, iv))
    }

    /// Create new value from variable length key and nonce.
    #[inline]
    fn new_from_slices(key: &[u8], iv: &[u8]) -> Result<Self, InvalidLength> {
        let key = <&Key<Self>>::try_from(key).map_err(|_| InvalidLength)?;
        let iv = <&Iv<Self>>::try_from(iv).map_err(|_| InvalidLength)?;
        Ok(Self::new(key, iv))
    }
}

/// Types which can be fallibly initialized from a key.
pub trait TryKeyInit: KeySizeUser + Sized {
    /// Create new value from a fixed-size key.
    ///
    /// # Errors
    /// - if the key is considered invalid according to rules specific to the implementing type
    fn new(key: &Key<Self>) -> Result<Self, InvalidKey>;

    /// Create new value from a variable size key.
    ///
    /// # Errors
    /// - if the provided slice is the wrong length
    /// - if the key is considered invalid by [`TryKeyInit::new`]
    #[inline]
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidKey> {
        <&Key<Self>>::try_from(key)
            .map_err(|_| InvalidKey)
            .and_then(Self::new)
    }
}

/// Types which can be initialized from another type (usually block ciphers).
///
/// Usually used for initializing types from block ciphers.
pub trait InnerInit: InnerUser + Sized {
    /// Initialize value from the `inner`.
    fn inner_init(inner: Self::Inner) -> Self;
}

/// Types which can be initialized from another type and additional initialization
/// vector/nonce.
///
/// Usually used for initializing types from block ciphers.
pub trait InnerIvInit: InnerUser + IvSizeUser + Sized {
    /// Initialize value using `inner` and `iv` array.
    fn inner_iv_init(inner: Self::Inner, iv: &Iv<Self>) -> Self;

    /// Initialize value using `inner` and `iv` slice.
    #[inline]
    fn inner_iv_slice_init(inner: Self::Inner, iv: &[u8]) -> Result<Self, InvalidLength> {
        let iv = <&Iv<Self>>::try_from(iv).map_err(|_| InvalidLength)?;
        Ok(Self::inner_iv_init(inner, iv))
    }
}

/// Trait for loading current IV state.
pub trait IvState: IvSizeUser {
    /// Returns current IV state.
    fn iv_state(&self) -> Iv<Self>;
}

impl<T> KeySizeUser for T
where
    T: InnerUser,
    T::Inner: KeySizeUser,
{
    type KeySize = <T::Inner as KeySizeUser>::KeySize;
}

impl<T> KeyIvInit for T
where
    T: InnerIvInit,
    T::Inner: KeyInit,
{
    #[inline]
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        Self::inner_iv_init(T::Inner::new(key), iv)
    }

    #[inline]
    fn new_from_slices(key: &[u8], iv: &[u8]) -> Result<Self, InvalidLength> {
        T::Inner::new_from_slice(key).and_then(|i| T::inner_iv_slice_init(i, iv))
    }

    #[inline]
    fn weak_key_test(key: &Key<Self>) -> Result<(), WeakKeyError> {
        T::Inner::weak_key_test(key)
    }
}

impl<T> KeyInit for T
where
    T: InnerInit,
    T::Inner: KeyInit,
{
    #[inline]
    fn new(key: &Key<Self>) -> Self {
        Self::inner_init(T::Inner::new(key))
    }

    #[inline]
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        T::Inner::new_from_slice(key)
            .map_err(|_| InvalidLength)
            .map(Self::inner_init)
    }

    #[inline]
    fn weak_key_test(key: &Key<Self>) -> Result<(), WeakKeyError> {
        T::Inner::weak_key_test(key)
    }
}

// Unfortunately this blanket impl is impossible without mutually
// exclusive traits, see: https://github.com/rust-lang/rfcs/issues/1053
// or at the very least without: https://github.com/rust-lang/rust/issues/20400
/*
impl<T> KeyIvInit for T
where
    T: InnerInit,
    T::Inner: KeyIvInit,
{
    #[inline]
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        Self::inner_init(T::Inner::new(key, iv))
    }

    #[inline]
    fn new_from_slices(key: &[u8], iv: &[u8]) -> Result<Self, InvalidLength> {
        T::Inner::new_from_slice(key)
            .map_err(|_| InvalidLength)
            .map(Self::inner_init)
    }

    #[inline]
    fn weak_key_test(key: &Key<Self>) -> Result<(), WeakKeyError> {
        T::Inner::weak_key_test(key)
    }
}
*/

/// Error type for [`TryKeyInit`] for cases where the provided bytes do not correspond to a
/// valid key.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct InvalidKey;

impl fmt::Display for InvalidKey {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("WeakKey")
    }
}

impl core::error::Error for InvalidKey {}

/// The error type returned when key and/or IV used in the [`KeyInit`],
/// [`KeyIvInit`], and [`InnerIvInit`] slice-based methods had
/// an invalid length.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct InvalidLength;

impl fmt::Display for InvalidLength {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("Invalid Length")
    }
}

impl core::error::Error for InvalidLength {}

/// The error type returned when a key is found to be weak.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct WeakKeyError;

impl fmt::Display for WeakKeyError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("WeakKey")
    }
}

impl core::error::Error for WeakKeyError {}
