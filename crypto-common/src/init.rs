//! Traits related to types initialization.

use core::fmt;
use generic_array::{ArrayLength, GenericArray, typenum::Unsigned};

/// Types which can be initialized from a key.
pub trait KeyInit: Sized {
    /// Key size in bytes.
    type KeySize: ArrayLength<u8>;

    /// Create new value from fixed size key.
    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self;

    /// Create new value from variable size key.
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        if key.len() != Self::KeySize::to_usize() {
            Err(InvalidLength)
        } else {
            Ok(Self::new(GenericArray::from_slice(key)))
        }
    }

    /// Generate a random key using the provided [`CryptoRng`].
    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    #[inline]
    fn generate_key(mut rng: impl CryptoRng + RngCore) -> GenericArray<u8, Self::KeySize> {
        let mut key = GenericArray::<u8, Self::KeySize>::default();
        rng.fill_bytes(&mut key);
        key
    }
}


/// Types which can be initialized from key and initialization vector/nonce.
pub trait KeyIvInit: Sized {
    /// Key size in bytes.
    type KeySize: ArrayLength<u8>;

    /// Initialization vector size in bytes.
    type IvSize: ArrayLength<u8>;

    /// Create new value from fixed length key and nonce.
    fn new(
        key: &GenericArray<u8, Self::KeySize>,
        iv: &GenericArray<u8, Self::IvSize>,
    ) -> Self;

    /// Create new value from variable length key and nonce.
    #[inline]
    fn new_from_slices(key: &[u8], iv: &[u8]) -> Result<Self, InvalidLength> {
        let kl = Self::KeySize::to_usize();
        let nl = Self::IvSize::to_usize();
        if key.len() != kl || iv.len() != nl {
            Err(InvalidLength)
        } else {
            let key = GenericArray::from_slice(key);
            let iv = GenericArray::from_slice(iv);
            Ok(Self::new(key, iv))
        }
    }

    /// Generate a random key using the provided [`CryptoRng`].
    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    #[inline]
    fn generate_key(mut rng: impl CryptoRng + RngCore) -> GenericArray<u8, Self::KeySize> {
        let mut key = GenericArray::<u8, Self::KeySize>::default();
        rng.fill_bytes(&mut key);
        key
    }

    /// Generate a random IV using the provided [`CryptoRng`].
    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    #[inline]
    fn generate_iv(mut rng: impl CryptoRng + RngCore) -> GenericArray<u8, Self::IvSize> {
        let mut iv = GenericArray::<u8, Self::IvSize>::default();
        rng.fill_bytes(&mut iv);
        iv
    }

    /// Generate random key and nonce using the provided [`CryptoRng`].
    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    #[inline]
    fn generate_key_iv(
        mut rng: impl CryptoRng + RngCore,
    ) -> (
        GenericArray<u8, Self::KeySize>,
        GenericArray<u8, Self::IvSize>,
    ) {
        (Self::generate_key(&mut rng), Self::generate_iv(&mut rng))
    }
}

/// Types which can be initialized from another type (usually block ciphers).
///
/// Usually used for initializing types from block ciphers.
pub trait InnerInit: Sized {
    /// Type used for initialization.
    type Inner;

    /// Initialize value from the `inner`.
    fn inner_init(inner: Self::Inner) -> Self;
}

/// Types which can be initialized from another type and additional initialization
/// vector/nonce.
///
/// Usually used for initializing types from block ciphers.
pub trait InnerIvInit: Sized {
    /// Block cipher used for initialization.
    type Inner;
    /// Initialization vector size in bytes.
    type IvSize: ArrayLength<u8>;

    /// Initialize value using `inner` and `iv` array.
    fn inner_iv_init(
        inner: Self::Inner,
        iv: &GenericArray<u8, Self::IvSize>,
    ) -> Self;

    /// Initialize value using `inner` and `iv` slice.
    fn inner_iv_slice_init(
        inner: Self::Inner,
        iv: &[u8],
    ) -> Result<Self, InvalidLength> {
        if iv.len() != Self::IvSize::to_usize() {
            Err(InvalidLength)
        } else {
            Ok(Self::inner_iv_init(inner, GenericArray::from_slice(iv)))
        }
    }
}

impl<T> KeyIvInit for T
where
    T: InnerIvInit,
    T::Inner: KeyInit,
{
    type KeySize = <T::Inner as KeyInit>::KeySize;
    type IvSize = T::IvSize;

    #[inline]
    fn new(
        key: &GenericArray<u8, Self::KeySize>,
        iv: &GenericArray<u8, Self::IvSize>,
    ) -> Self {
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
    type KeySize = <T::Inner as KeyInit>::KeySize;

    #[inline]
    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        Self::inner_init(T::Inner::new(key))
    }

    #[inline]
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        T::Inner::new_from_slice(key)
            .map_err(|_| InvalidLength)
            .map(Self::inner_init)
    }
}

/// The error type returned when key and/or IV used in the [`FromKey`]
/// and [`FromKeyIv`] slice-based methods had an invalid length.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct InvalidLength;

impl fmt::Display for InvalidLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("Invalid Length")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidLength {}

