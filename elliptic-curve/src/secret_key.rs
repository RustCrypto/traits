//! Secret keys for elliptic curves (i.e. private scalars)
//!
//! The [`SecretKey`] type is a wrapper around a secret scalar value which is
//! designed to prevent unintentional exposure (e.g. via `Debug` or other
//! logging).
//!
//! When the `zeroize` feature of this crate is enabled, it also handles
//! zeroing it out of memory securely on drop.

use crate::{error::Error, Curve, ElementBytes};
use core::{
    convert::{TryFrom, TryInto},
    fmt::{self, Debug},
};
use generic_array::{typenum::Unsigned, GenericArray};

#[cfg(feature = "rand")]
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
    scalar: ElementBytes<C>,
}

impl<C: Curve> SecretKey<C> {
    /// Create a new secret key from a serialized scalar value
    pub fn new(bytes: ElementBytes<C>) -> Self {
        Self { scalar: bytes }
    }

    /// Deserialize this secret key from a bytestring
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        bytes.as_ref().try_into()
    }

    /// Expose the byte serialization of the value this [`SecretKey`] wraps
    pub fn as_bytes(&self) -> &ElementBytes<C> {
        &self.scalar
    }
}

impl<C: Curve> TryFrom<&[u8]> for SecretKey<C> {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Error> {
        if slice.len() == C::FieldSize::to_usize() {
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

#[cfg(feature = "rand")]
#[cfg_attr(docsrs, doc(cfg(feature = "rand")))]
impl<C> Generate for SecretKey<C>
where
    C: Curve + Arithmetic,
    C::Scalar: Generate + Into<ElementBytes<C>>,
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
