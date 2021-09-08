//! Secret keys for elliptic curves (i.e. private scalars).
//!
//! The [`SecretKey`] type is a wrapper around a secret scalar value which is
//! designed to prevent unintentional exposure (e.g. via `Debug` or other
//! logging).
//!
//! When the `zeroize` feature of this crate is enabled, it also handles
//! zeroing it out of memory securely on drop.

#[cfg(feature = "pkcs8")]
mod pkcs8;

use crate::{Curve, Error, FieldBytes, Result, ScalarCore};
use core::{
    convert::TryFrom,
    fmt::{self, Debug},
};
use crypto_bigint::Encoding;
use generic_array::GenericArray;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

#[cfg(feature = "arithmetic")]
use crate::{
    rand_core::{CryptoRng, RngCore},
    NonZeroScalar, ProjectiveArithmetic, PublicKey, Scalar,
};

#[cfg(feature = "jwk")]
use crate::{
    generic_array::{typenum::U1, ArrayLength},
    jwk::{JwkEcKey, JwkParameters},
    ops::Add,
    sec1::{UncompressedPointSize, UntaggedPointSize, ValidatePublicKey},
};

#[cfg(all(feature = "arithmetic", feature = "jwk"))]
use {
    crate::{
        sec1::{FromEncodedPoint, ToEncodedPoint},
        AffinePoint, PrimeCurve,
    },
    alloc::string::{String, ToString},
};

#[cfg(all(docsrs, feature = "pkcs8"))]
use {crate::pkcs8::FromPrivateKey, core::str::FromStr};

/// Elliptic curve secret keys.
///
/// This type wraps a secret scalar value, helping to prevent accidental
/// exposure and securely erasing the value from memory when dropped.
///
/// # Parsing PKCS#8 Keys
///
/// PKCS#8 is a commonly used format for encoding secret keys (especially ones
/// generated by OpenSSL).
///
/// Keys in PKCS#8 format are either binary (ASN.1 BER/DER), or PEM encoded
/// (ASCII) and begin with the following:
///
/// ```text
/// -----BEGIN PRIVATE KEY-----
/// ```
///
/// To decode an elliptic curve private key from PKCS#8, enable the `pkcs8`
/// feature of this crate (or the `pkcs8` feature of a specific RustCrypto
/// elliptic curve crate) and use the
/// [`elliptic_curve::pkcs8::FromPrivateKey`][`FromPrivateKey`]
/// trait to parse it.
///
/// When the `pem` feature of this crate (or a specific RustCrypto elliptic
/// curve crate) is enabled, a [`FromStr`] impl is also available.
#[derive(Clone)]
pub struct SecretKey<C: Curve> {
    /// Scalar value
    inner: ScalarCore<C>,
}

impl<C> SecretKey<C>
where
    C: Curve,
{
    /// Generate a random [`SecretKey`].
    #[cfg(feature = "arithmetic")]
    #[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
    pub fn random(rng: impl CryptoRng + RngCore) -> Self
    where
        C: ProjectiveArithmetic,
        Scalar<C>: Zeroize,
    {
        Self {
            inner: NonZeroScalar::<C>::random(rng).into(),
        }
    }

    /// Create a new secret key from a scalar value.
    pub fn new(scalar: ScalarCore<C>) -> Self {
        Self { inner: scalar }
    }

    /// Deserialize raw private scalar as a big endian integer.
    pub fn from_bytes_be(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != C::UInt::BYTE_SIZE {
            return Err(Error);
        }

        let inner: ScalarCore<C> = Option::from(ScalarCore::from_bytes_be(
            GenericArray::clone_from_slice(bytes),
        ))
        .ok_or(Error)?;

        if inner.is_zero().into() {
            return Err(Error);
        }

        Ok(Self { inner })
    }

    /// Expose the byte serialization of the value this [`SecretKey`] wraps.
    pub fn to_bytes_be(&self) -> FieldBytes<C> {
        self.inner.to_bytes_be()
    }

    /// Borrow the inner secret [`ScalarCore`] value.
    ///
    /// # Warning
    ///
    /// This value is key material.
    ///
    /// Please treat it with the care it deserves!
    pub fn as_secret_scalar(&self) -> &ScalarCore<C> {
        &self.inner
    }

    /// Get the secret scalar value for this key.
    #[cfg(feature = "arithmetic")]
    #[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
    pub fn to_secret_scalar(&self) -> NonZeroScalar<C>
    where
        C: Curve + ProjectiveArithmetic,
        Scalar<C>: Zeroize,
    {
        self.into()
    }

    /// Get the [`PublicKey`] which corresponds to this secret key
    #[cfg(feature = "arithmetic")]
    #[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
    pub fn public_key(&self) -> PublicKey<C>
    where
        C: Curve + ProjectiveArithmetic,
        Scalar<C>: Zeroize,
    {
        PublicKey::from_secret_scalar(&self.to_secret_scalar())
    }

    /// Parse a [`JwkEcKey`] JSON Web Key (JWK) into a [`SecretKey`].
    #[cfg(feature = "jwk")]
    #[cfg_attr(docsrs, doc(cfg(feature = "jwk")))]
    pub fn from_jwk(jwk: &JwkEcKey) -> Result<Self>
    where
        C: JwkParameters + ValidatePublicKey,
        UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
        UncompressedPointSize<C>: ArrayLength<u8>,
    {
        Self::try_from(jwk)
    }

    /// Parse a string containing a JSON Web Key (JWK) into a [`SecretKey`].
    #[cfg(feature = "jwk")]
    #[cfg_attr(docsrs, doc(cfg(feature = "jwk")))]
    pub fn from_jwk_str(jwk: &str) -> Result<Self>
    where
        C: JwkParameters + ValidatePublicKey,
        UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
        UncompressedPointSize<C>: ArrayLength<u8>,
    {
        jwk.parse::<JwkEcKey>().and_then(|jwk| Self::from_jwk(&jwk))
    }

    /// Serialize this secret key as [`JwkEcKey`] JSON Web Key (JWK).
    #[cfg(all(feature = "arithmetic", feature = "jwk"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
    #[cfg_attr(docsrs, doc(cfg(feature = "jwk")))]
    pub fn to_jwk(&self) -> JwkEcKey
    where
        C: PrimeCurve + JwkParameters + ProjectiveArithmetic,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        Scalar<C>: Zeroize,
        UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
        UncompressedPointSize<C>: ArrayLength<u8>,
    {
        self.into()
    }

    /// Serialize this secret key as JSON Web Key (JWK) string.
    #[cfg(all(feature = "arithmetic", feature = "jwk"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
    #[cfg_attr(docsrs, doc(cfg(feature = "jwk")))]
    pub fn to_jwk_string(&self) -> String
    where
        C: PrimeCurve + JwkParameters + ProjectiveArithmetic,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        Scalar<C>: Zeroize,
        UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
        UncompressedPointSize<C>: ArrayLength<u8>,
    {
        self.to_jwk().to_string()
    }
}

impl<C> ConstantTimeEq for SecretKey<C>
where
    C: Curve,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.inner.ct_eq(&other.inner)
    }
}

impl<C> Debug for SecretKey<C>
where
    C: Curve,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO(tarcieri): use `debug_struct` and `finish_non_exhaustive` when stable
        write!(f, "SecretKey<{:?}>{{ ... }}", C::default())
    }
}

impl<C> Drop for SecretKey<C>
where
    C: Curve,
{
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl<C: Curve> Eq for SecretKey<C> {}

impl<C> PartialEq for SecretKey<C>
where
    C: Curve,
{
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<C> TryFrom<&[u8]> for SecretKey<C>
where
    C: Curve,
{
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self> {
        Self::from_bytes_be(slice)
    }
}

#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
impl<C> From<NonZeroScalar<C>> for SecretKey<C>
where
    C: Curve + ProjectiveArithmetic,
{
    fn from(scalar: NonZeroScalar<C>) -> SecretKey<C> {
        SecretKey::from(&scalar)
    }
}

#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
impl<C> From<&NonZeroScalar<C>> for SecretKey<C>
where
    C: Curve + ProjectiveArithmetic,
{
    fn from(scalar: &NonZeroScalar<C>) -> SecretKey<C> {
        SecretKey {
            inner: scalar.into(),
        }
    }
}
