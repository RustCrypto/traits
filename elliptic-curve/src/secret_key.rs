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
    group::{Curve as _, Group},
    public_key::PublicKey,
    rand_core::{CryptoRng, RngCore},
    scalar::{NonZeroScalar, Scalar},
    weierstrass, AffinePoint, ProjectiveArithmetic,
};

#[cfg(feature = "pkcs8")]
use crate::{generic_array::typenum::Unsigned, AlgorithmParameters, ALGORITHM_OID};

#[cfg(feature = "pem")]
use core::str::FromStr;

/// Inner value stored by a [`SecretKey`].
pub trait SecretValue: Curve {
    /// Inner secret value.
    ///
    /// ⚠️ WARNING ⚠️
    ///
    /// This type is not intended to be part of the public API and in future
    /// versions of this crate we will try to explore ways to hide it.
    ///
    /// Crates such as `k256` and `p256` conditionally define this type
    /// differently depending on what cargo features are enabled.
    /// This means any consumers of this crate attempting to use this type
    /// may experience breakages if the cargo features are not what are
    /// expected.
    ///
    /// We regret exposing it as part of the public API for now, however if
    /// you do reference this type as a downstream consumer of a curve crate,
    /// be aware you will experience breakages!
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

    /// Deserialize raw private scalar as a big endian integer
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        bytes
            .as_ref()
            .try_into()
            .ok()
            .and_then(C::from_secret_bytes)
            .map(|secret_value| SecretKey { secret_value })
            .ok_or(Error)
    }

    /// Deserialize PKCS#8-encoded private key from ASN.1 DER
    /// (binary format).
    #[cfg(feature = "pkcs8")]
    #[cfg_attr(docsrs, doc(cfg(feature = "pkcs8")))]
    pub fn from_pkcs8_der(bytes: &[u8]) -> Result<Self, Error>
    where
        C: AlgorithmParameters,
    {
        Self::from_pkcs8_private_key_info(pkcs8::PrivateKeyInfo::from_der(bytes)?)
    }

    /// Deserialize PKCS#8-encoded private key from PEM.
    ///
    /// Keys in this format begin with the following delimiter:
    ///
    /// ```text
    /// -----BEGIN PRIVATE KEY-----
    /// ```
    #[cfg(feature = "pem")]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    pub fn from_pkcs8_pem(s: &str) -> Result<Self, Error>
    where
        C: AlgorithmParameters,
    {
        let pkcs8_doc = pkcs8::Document::from_pem(s)?;
        Self::from_pkcs8_private_key_info(pkcs8_doc.private_key_info())
    }

    /// Parse the `private_key` field of a PKCS#8-encoded private key's
    /// `PrivateKeyInfo`.
    #[cfg(feature = "pkcs8")]
    #[cfg_attr(docsrs, doc(cfg(feature = "pkcs8")))]
    fn from_pkcs8_private_key_info(
        private_key_info: pkcs8::PrivateKeyInfo<'_>,
    ) -> Result<Self, Error>
    where
        C: AlgorithmParameters,
    {
        if private_key_info.algorithm.oid != ALGORITHM_OID
            || private_key_info.algorithm.parameters != Some(C::OID)
        {
            return Err(Error);
        }

        let bytes = private_key_info.private_key;

        // Ensure private key is AT LEAST as long as a scalar field element
        // for this curve along with the following overhead:
        //
        // 2-bytes: SEQUENCE header: tag byte + length
        // 3-bytes: INTEGER version: tag byte + length + value
        // 2-bytes: OCTET STRING header: tag byte + length
        if bytes.len() < 2 + 3 + 2 + C::FieldSize::to_usize() {
            return Err(Error);
        }

        // Check key begins with ASN.1 DER SEQUENCE tag (0x30) + valid length,
        // where the length omits the leading SEQUENCE header (tag + length byte)
        if bytes[0] != 0x30 || bytes[1].checked_add(2).unwrap() as usize != bytes.len() {
            return Err(Error);
        }

        // Validate version field (ASN.1 DER INTEGER value: 1)
        if bytes[2..=4] != [0x02, 0x01, 0x01] {
            return Err(Error);
        }

        // Validate ASN.1 DER OCTET STRING header: tag (0x04) + valid length
        if bytes[5] != 0x04 || bytes[6] as usize != C::FieldSize::to_usize() {
            return Err(Error);
        }

        // TODO(tarcieri): extract and validate public key
        Ok(Self::from_bytes(&bytes[7..(7 + C::FieldSize::to_usize())])?)
    }

    /// Expose the byte serialization of the value this [`SecretKey`] wraps
    pub fn to_bytes(&self) -> FieldBytes<C> {
        self.secret_value.clone().into()
    }

    /// Borrow the inner generic secret value.
    ///
    /// # Warning
    ///
    /// This value is key material.
    ///
    /// Please treat it with the care it deserves!
    pub fn secret_value(&self) -> &C::Secret {
        &self.secret_value
    }

    /// Borrow the inner secret [`Scalar`] value.
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

    /// Get the [`PublicKey`] which corresponds to this secret key
    #[cfg(feature = "arithmetic")]
    #[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
    pub fn public_key(&self) -> PublicKey<C>
    where
        C: weierstrass::Curve + ProjectiveArithmetic + SecretValue<Secret = NonZeroScalar<C>>,
        FieldBytes<C>: From<Scalar<C>> + for<'a> From<&'a Scalar<C>>,
        Scalar<C>: PrimeField<Repr = FieldBytes<C>> + Zeroize,
        AffinePoint<C>: Copy + Clone + Debug + Default,
    {
        PublicKey::from_affine((C::ProjectivePoint::generator() * self.secret_scalar()).to_affine())
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

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
impl<C> FromStr for SecretKey<C>
where
    C: Curve + AlgorithmParameters + SecretValue,
    C::Secret: Clone + Zeroize,
    FieldBytes<C>: From<C::Secret>,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Self::from_pkcs8_pem(s)
    }
}

impl<C> Debug for SecretKey<C>
where
    C: Curve + SecretValue,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO(tarcieri): use `debug_struct` and `finish_non_exhaustive` when stable
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
#[derive(Clone)]
pub struct SecretBytes<C: Curve>(FieldBytes<C>);

impl<C: Curve> From<FieldBytes<C>> for SecretBytes<C> {
    fn from(bytes: FieldBytes<C>) -> SecretBytes<C> {
        Self(bytes)
    }
}

impl<C: Curve> From<SecretBytes<C>> for FieldBytes<C> {
    fn from(bytes: SecretBytes<C>) -> FieldBytes<C> {
        bytes.0
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
