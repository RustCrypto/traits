//! Secret keys for elliptic curves (i.e. private scalars)
//!
//! The [`SecretKey`] type wraps the [`ScalarBytes`] byte array type with
//! a wrapper designed to prevent unintentional exposure of the scalar
//! value (e.g. via `Debug` or other logging).
//!
//! When the `zeroize` feature of this crate is enabled, it also handles
//! zeroing it out of memory securely on drop.

use crate::{error::Error, Curve, ScalarBytes};
use core::{
    convert::{TryFrom, TryInto},
    fmt::{self, Debug},
};
use generic_array::{typenum::Unsigned, GenericArray};
use subtle::CtOption;

#[cfg(feature = "rand_core")]
use {
    crate::{Arithmetic, Generate},
    rand_core::{CryptoRng, RngCore},
};

/// Elliptic curve secret keys.
///
/// This type wraps a serialized scalar value, helping to prevent accidental
/// exposure and securely erasing the value from memory when dropped
/// (when the `zeroize` feature of this crate is enabled).
#[derive(Clone)]
pub struct SecretKey<C: Curve> {
    /// Private scalar value
    scalar: ScalarBytes<C>,
}

impl<C: Curve> SecretKey<C> {
    /// Create a new secret key from a serialized scalar value
    pub fn new(bytes: ScalarBytes<C>) -> Self {
        Self { scalar: bytes }
    }

    /// Deserialize this secret key from a bytestring
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        bytes.as_ref().try_into()
    }

    /// Expose the secret [`ScalarBytes`] value this [`SecretKey`] wraps
    pub fn secret_scalar(&self) -> &ScalarBytes<C> {
        &self.scalar
    }
}

impl<C: Curve> TryFrom<&[u8]> for SecretKey<C> {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Error> {
        if slice.len() == C::ElementSize::to_usize() {
            Ok(SecretKey {
                scalar: GenericArray::clone_from_slice(slice),
            })
        } else {
            Err(Error)
        }
    }
}

impl<C: Curve> Debug for SecretKey<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey<{:?}>{{ ... }}", C::default())
    }
}

#[cfg(feature = "rand_core")]
#[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
impl<C> Generate for SecretKey<C>
where
    C: Curve + Arithmetic,
    C::Scalar: Generate + Into<ScalarBytes<C>>,
{
    /// Generate a new [`SecretKey`]
    fn generate(rng: impl CryptoRng + RngCore) -> Self {
        Self {
            scalar: C::Scalar::generate(rng).into(),
        }
    }
}

#[cfg(feature = "zeroize")]
impl<C: Curve> Drop for SecretKey<C> {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.scalar.zeroize();
    }
}

/// Trait for deserializing a value from a secret key.
///
/// This is intended for use with the `Scalar` type for a given elliptic curve.
pub trait FromSecretKey<C: Curve>: Sized {
    /// Deserialize this value from a [`SecretKey`]
    fn from_secret_key(secret_key: &SecretKey<C>) -> CtOption<Self>;
}
