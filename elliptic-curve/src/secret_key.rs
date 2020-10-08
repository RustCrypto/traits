//! Secret keys for elliptic curves (i.e. private scalars)
//!
//! The [`SecretKey`] type is a wrapper around a secret scalar value which is
//! designed to prevent unintentional exposure (e.g. via `Debug` or other
//! logging).
//!
//! When the `zeroize` feature of this crate is enabled, it also handles
//! zeroing it out of memory securely on drop.

use crate::{error::Error, Curve, FieldBytes};
use core::{
    convert::{TryFrom, TryInto},
    fmt::{self, Debug},
    ops::Deref,
};
use zeroize::Zeroize;

#[cfg(feature = "arithmetic")]
use crate::{
    ff::PrimeField,
    scalar::{NonZeroScalar, Scalar},
    ProjectiveArithmetic,
};
#[cfg(feature = "arithmetic")]
use rand_core::{CryptoRng, RngCore};

/// Inner value stored by a [`SecretKey`].
pub trait SecretValue: Curve {
    /// Inner secret value
    type Secret: Into<FieldBytes<Self>> + Zeroize;

    /// Parse the secret value from bytes
    // TODO(tarcieri): make this constant time?
    fn from_secret_bytes(bytes: &FieldBytes<Self>) -> Option<Self::Secret>;
}

#[cfg(feature = "arithmetic")]
impl<C> SecretValue for C
where
    C: Curve + ProjectiveArithmetic,
    FieldBytes<C>: From<Scalar<C>> + for<'a> From<&'a Scalar<C>>,
    Scalar<C>: PrimeField<Repr = FieldBytes<C>> + Zeroize,
{
    type Secret = NonZeroScalar<C>;

    fn from_secret_bytes(repr: &FieldBytes<C>) -> Option<NonZeroScalar<C>> {
        NonZeroScalar::from_repr(repr.clone())
    }
}

/// Elliptic curve secret keys.
///
/// This type wraps a secret scalar value, helping to prevent accidental
/// exposure and securely erasing the value from memory when dropped
/// (when the `zeroize` feature of this crate is enabled).
#[derive(Clone)]
pub struct SecretKey<C: Curve + SecretValue> {
    /// Secret value (i.e. secret scalar)
    secret_value: C::Secret,
}

impl<C> SecretKey<C>
where
    C: Curve + SecretValue,
    C::Secret: Clone + Zeroize,
    FieldBytes<C>: From<C::Secret>,
{
    /// Generate a random [`SecretKey`]
    #[cfg(feature = "arithmetic")]
    #[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
    pub fn random(rng: impl CryptoRng + RngCore) -> Self
    where
        C: ProjectiveArithmetic + SecretValue<Secret = NonZeroScalar<C>>,
        FieldBytes<C>: From<Scalar<C>> + for<'a> From<&'a Scalar<C>>,
        Scalar<C>: PrimeField<Repr = FieldBytes<C>> + Zeroize,
    {
        Self {
            secret_value: NonZeroScalar::<C>::random(rng),
        }
    }

    /// Create a new secret key from a serialized scalar value
    pub fn new(secret_value: C::Secret) -> Self {
        Self { secret_value }
    }

    /// Deserialize this secret key from a bytestring
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        bytes
            .as_ref()
            .try_into()
            .ok()
            .and_then(C::from_secret_bytes)
            .map(|secret_value| SecretKey { secret_value })
            .ok_or(Error)
    }

    /// Expose the byte serialization of the value this [`SecretKey`] wraps
    pub fn to_bytes(&self) -> FieldBytes<C> {
        self.secret_value.clone().into()
    }

    /// Borrow the inner secret scalar value.
    ///
    /// # Warning
    ///
    /// This value is key material.
    ///
    /// Please treat it with the care it deserves!
    #[cfg(feature = "arithmetic")]
    #[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
    pub fn secret_scalar(&self) -> &Scalar<C>
    where
        C: ProjectiveArithmetic + SecretValue<Secret = NonZeroScalar<C>>,
        FieldBytes<C>: From<Scalar<C>> + for<'a> From<&'a Scalar<C>>,
        Scalar<C>: PrimeField<Repr = FieldBytes<C>> + Zeroize,
    {
        self.secret_value.as_ref()
    }
}

impl<C> TryFrom<&[u8]> for SecretKey<C>
where
    C: Curve + SecretValue,
    C::Secret: Clone + Zeroize,
    FieldBytes<C>: From<C::Secret>,
{
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(slice)
    }
}

impl<C> Debug for SecretKey<C>
where
    C: Curve + SecretValue,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey<{:?}>{{ ... }}", C::default())
    }
}

impl<C> Drop for SecretKey<C>
where
    C: Curve + SecretValue,
{
    fn drop(&mut self) {
        self.secret_value.zeroize();
    }
}

/// Newtype wrapper for [`FieldBytes`] which impls [`Zeroize`].
///
/// This allows it to fulfill the [`Zeroize`] bound on [`SecretValue::Secret`].
pub struct SecretBytes<C: Curve>(FieldBytes<C>);

impl<C: Curve> From<FieldBytes<C>> for SecretBytes<C> {
    fn from(bytes: FieldBytes<C>) -> SecretBytes<C> {
        Self(bytes)
    }
}

impl<C: Curve> AsRef<[u8]> for SecretBytes<C> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<C: Curve> Deref for SecretBytes<C> {
    type Target = FieldBytes<C>;

    fn deref(&self) -> &FieldBytes<C> {
        &self.0
    }
}

impl<C: Curve> Zeroize for SecretBytes<C> {
    fn zeroize(&mut self) {
        self.0.as_mut().zeroize();
    }
}
