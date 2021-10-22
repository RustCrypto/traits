//! Traits related to types initialization.

use crate::users::{InnerUser, Iv, IvSizeUser, Key, KeySizeUser};
use core::fmt;
use generic_array::typenum::Unsigned;
#[cfg(feature = "rand_core")]
use rand_core::{CryptoRng, RngCore};

/// Types which can be initialized from key.
pub trait KeyInit: KeySizeUser + Sized {
    /// Create new value from fixed size key.
    fn new(key: &Key<Self>) -> Self;

    /// Create new value from variable size key.
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        if key.len() != Self::KeySize::to_usize() {
            Err(InvalidLength)
        } else {
            Ok(Self::new(Key::<Self>::from_slice(key)))
        }
    }
}

/// Types which can be initialized from key and initialization vector (nonce).
pub trait KeyIvInit: KeySizeUser + IvSizeUser + Sized {
    /// Create new value from fixed length key and nonce.
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self;

    /// Create new value from variable length key and nonce.
    #[inline]
    fn new_from_slices(key: &[u8], iv: &[u8]) -> Result<Self, InvalidLength> {
        let key_len = Self::KeySize::USIZE;
        let iv_len = Self::IvSize::USIZE;
        if key.len() != key_len || iv.len() != iv_len {
            Err(InvalidLength)
        } else {
            Ok(Self::new(
                Key::<Self>::from_slice(key),
                Iv::<Self>::from_slice(iv),
            ))
        }
    }

    /// Generate random key and nonce using the provided [`CryptoRng`].
    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    #[inline]
    fn generate_key_iv(mut rng: impl CryptoRng + RngCore) -> (Key<Self>, Iv<Self>) {
        (Self::generate_key(&mut rng), Self::generate_iv(&mut rng))
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
    fn inner_iv_slice_init(inner: Self::Inner, iv: &[u8]) -> Result<Self, InvalidLength> {
        if iv.len() != Self::IvSize::to_usize() {
            Err(InvalidLength)
        } else {
            Ok(Self::inner_iv_init(inner, Iv::<Self>::from_slice(iv)))
        }
    }
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
}
*/

/// The error type returned when key and/or IV used in the [`KeyInit`],
/// [`KeyIvInit`], and [`InnerIvInit`] slice-based methods had
/// an invalid length.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct InvalidLength;

impl fmt::Display for InvalidLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("Invalid Length")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidLength {}
