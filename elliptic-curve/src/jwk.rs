//! JSON Web Key (JWK) Support.
//!
//! Specified in RFC 7518 Section 6: Cryptographic Algorithms for Keys:
//! <https://tools.ietf.org/html/rfc7518#section-6>

use crate::{
    sec1::{Coordinates, EncodedPoint, ModulusSize, ValidatePublicKey},
    secret_key::SecretKey,
    Curve, Error, FieldBytes, FieldBytesSize, Result,
};
use alloc::{
    borrow::ToOwned,
    format,
    string::{String, ToString},
};
use base64ct::{Base64UrlUnpadded as Base64Url, Encoding};
use core::{
    fmt::{self, Debug},
    str::{self, FromStr},
};
use serdect::serde::{de, Deserialize, Serialize};
use sha2::Digest;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "arithmetic")]
use crate::{
    public_key::PublicKey,
    sec1::{FromEncodedPoint, ToEncodedPoint},
    AffinePoint, CurveArithmetic,
};

/// Key Type (`kty`) for elliptic curve keys.
pub const EC_KTY: &str = "EC";

/// Name of the JWK type
const JWK_TYPE_NAME: &str = "JwkEcKey";

/// Elliptic curve parameters used by JSON Web Keys.
pub trait JwkParameters: Curve {
    /// The `crv` parameter which identifies a particular elliptic curve
    /// as defined in RFC 7518 Section 6.2.1.1:
    /// <https://tools.ietf.org/html/rfc7518#section-6.2.1.1>
    ///
    /// Curve values are registered in the IANA "JSON Web Key Elliptic Curve"
    /// registry defined in RFC 7518 Section 7.6:
    /// <https://tools.ietf.org/html/rfc7518#section-7.6>
    const CRV: &'static str;
}

/// JSON Web Key (JWK) with a `kty` of `"EC"` (elliptic curve).
///
/// Specified in [RFC 7518 Section 6: Cryptographic Algorithms for Keys][1].
///
/// This type can represent either a public/private keypair, or just a
/// public key, depending on whether or not the `d` parameter is present.
///
/// [1]: https://tools.ietf.org/html/rfc7518#section-6
// TODO(tarcieri): eagerly decode or validate `x`, `y`, and `d` as Base64
#[derive(Clone, Deserialize, Serialize)]
#[serde(crate = "serdect::serde")]
pub struct JwkEcKey {
    /// The `crv` parameter which identifies a particular elliptic curve
    /// as defined in RFC 7518 Section 6.2.1.1:
    /// <https://tools.ietf.org/html/rfc7518#section-6.2.1.1>
    pub crv: String,

    /// The x-coordinate of the elliptic curve point which is the public key
    /// value associated with this JWK as defined in RFC 7518 6.2.1.2:
    /// <https://tools.ietf.org/html/rfc7518#section-6.2.1.2>
    pub x: String,

    /// The y-coordinate of the elliptic curve point which is the public key
    /// value associated with this JWK as defined in RFC 7518 6.2.1.3:
    /// <https://tools.ietf.org/html/rfc7518#section-6.2.1.3>
    pub y: String,

    /// The `d` ECC private key parameter as described in RFC 7518 6.2.2.1:
    /// <https://tools.ietf.org/html/rfc7518#section-6.2.2.1>
    ///
    /// Value is optional and if omitted, this JWK represents a private key.
    ///
    /// Inner value is encoded according to the `Integer-to-Octet-String`
    /// conversion as defined in SEC1 section 2.3.7:
    /// <https://www.secg.org/sec1-v2.pdf>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,

    /// Key Type (must be "EC" if present) as described in RFC 7517 4.1:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.1>
    ///
    /// Value is optional.
    ///
    /// For Elliptic-Curve the value must be "EC".
    #[serde(deserialize_with = "deserialize_kty")]
    pub kty: String,

    /// The Public Key Use as described in RFC 7517 4.2:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.2>
    ///
    /// Value is optional and not used by this crate.
    #[serde(skip_serializing_if = "Option::is_none", rename = "use")]
    pub use_: Option<String>,

    /// The Key Operations as described in RFC 7517 4.3:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.3>
    ///
    /// Value is optional and not used by this crate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<alloc::vec::Vec<String>>,

    /// The Algorithm as described in RFC 7517 4.4:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.4>
    ///
    /// Value is optional and not used by this crate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    /// The Key ID as described in RFC 7517 4.5:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.5>
    ///
    /// Value is optional and not used by this crate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// The X.509 URL as described in RFC 7517 4.6:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.6>
    ///
    /// Value is optional and not used by this crate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,

    /// The X.509 Certificate Chain as described in RFC 7517 4.7:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.7>
    ///
    /// Value is optional and not used by this crate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<String>,

    /// The X.509 Certificate SHA-1 Thumbprint as described in RFC 7517 4.8:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.8>
    ///
    /// Value is optional and not used by this crate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,

    /// The X.509 Certificate SHA-256 as described in RFC 7517 4.9:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.9>
    ///
    /// Value is optional and not used by this crate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
}

fn deserialize_kty<'de, D>(deserializer: D) -> core::result::Result<String, D::Error>
where
    D: serdect::serde::Deserializer<'de>,
{
    let kty: &str = Deserialize::deserialize(deserializer)?;
    if kty != EC_KTY {
        return Err(de::Error::custom(format!("unsupported JWK kty: {kty:?}")));
    }

    Ok(kty.to_string())
}

impl JwkEcKey {
    /// Get the `crv` parameter for this JWK.
    pub fn crv(&self) -> &str {
        &self.crv
    }

    /// Is this JWK a keypair that includes a private key?
    pub fn is_keypair(&self) -> bool {
        self.d.is_some()
    }

    /// Does this JWK contain only a public key?
    pub fn is_public_key(&self) -> bool {
        self.d.is_none()
    }

    /// Decode a JWK into a [`PublicKey`].
    #[cfg(feature = "arithmetic")]
    pub fn to_public_key<C>(&self) -> Result<PublicKey<C>>
    where
        C: CurveArithmetic + JwkParameters,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        FieldBytesSize<C>: ModulusSize,
    {
        PublicKey::from_sec1_bytes(self.to_encoded_point::<C>()?.as_bytes())
    }

    /// Create a JWK from a SEC1 [`EncodedPoint`].
    pub fn from_encoded_point<C>(point: &EncodedPoint<C>) -> Option<Self>
    where
        C: Curve + JwkParameters,
        FieldBytesSize<C>: ModulusSize,
    {
        match point.coordinates() {
            Coordinates::Uncompressed { x, y } => Some(JwkEcKey {
                crv: C::CRV.to_owned(),
                x: Base64Url::encode_string(x),
                y: Base64Url::encode_string(y),
                d: None,
                alg: None,
                key_ops: None,
                kid: None,
                kty: EC_KTY.into(),
                use_: None,
                x5c: None,
                x5t: None,
                x5t_s256: None,
                x5u: None,
            }),
            _ => None,
        }
    }

    /// Generates the thumbprint for JWK as defined in RFC 7638 (
    /// <https://datatracker.ietf.org/doc/html/rfc7638>).
    pub fn thumbprint(&self) -> Result<String> {
        // For EC type the following fields are required to be
        // present and in lexicographic order
        #[derive(Serialize)]
        #[serde(crate = "serdect::serde")]
        struct Required {
            crv: String,
            kty: String,
            x: String,
            y: String,
        }

        let required_fields = Required {
            crv: self.crv.to_owned(),
            kty: self.kty.to_owned(),
            x: self.x.to_owned(),
            y: self.y.to_owned(),
        };

        let mut hasher = sha2::Sha256::new();
        hasher.update(
            serde_json::to_string(&required_fields)
                .map_err(|_| Error)?
                .as_bytes(),
        );
        Ok(base64ct::Base64UrlUnpadded::encode_string(
            &hasher.finalize(),
        ))
    }

    /// Get the public key component of this JWK as a SEC1 [`EncodedPoint`].
    pub fn to_encoded_point<C>(&self) -> Result<EncodedPoint<C>>
    where
        C: Curve + JwkParameters,
        FieldBytesSize<C>: ModulusSize,
    {
        if self.crv != C::CRV {
            return Err(Error);
        }

        let x = decode_base64url_fe::<C>(&self.x)?;
        let y = decode_base64url_fe::<C>(&self.y)?;
        Ok(EncodedPoint::<C>::from_affine_coordinates(&x, &y, false))
    }

    /// Decode a JWK into a [`SecretKey`].
    #[cfg(feature = "arithmetic")]
    pub fn to_secret_key<C>(&self) -> Result<SecretKey<C>>
    where
        C: Curve + JwkParameters + ValidatePublicKey,
        FieldBytesSize<C>: ModulusSize,
    {
        self.try_into()
    }
}

impl FromStr for JwkEcKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|_| Error)
    }
}

impl ToString for JwkEcKey {
    fn to_string(&self) -> String {
        serde_json::to_string(self).expect("JWK encoding error")
    }
}

impl<C> TryFrom<JwkEcKey> for SecretKey<C>
where
    C: Curve + JwkParameters + ValidatePublicKey,
    FieldBytesSize<C>: ModulusSize,
{
    type Error = Error;

    fn try_from(jwk: JwkEcKey) -> Result<SecretKey<C>> {
        (&jwk).try_into()
    }
}

impl<C> TryFrom<&JwkEcKey> for SecretKey<C>
where
    C: Curve + JwkParameters + ValidatePublicKey,
    FieldBytesSize<C>: ModulusSize,
{
    type Error = Error;

    fn try_from(jwk: &JwkEcKey) -> Result<SecretKey<C>> {
        if let Some(d_base64) = &jwk.d {
            let pk = jwk.to_encoded_point::<C>()?;
            let mut d_bytes = decode_base64url_fe::<C>(d_base64)?;
            let result = SecretKey::from_slice(&d_bytes);
            d_bytes.zeroize();

            result.and_then(|secret_key| {
                C::validate_public_key(&secret_key, &pk)?;
                Ok(secret_key)
            })
        } else {
            Err(Error)
        }
    }
}

#[cfg(feature = "arithmetic")]
impl<C> From<SecretKey<C>> for JwkEcKey
where
    C: CurveArithmetic + JwkParameters,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    fn from(sk: SecretKey<C>) -> JwkEcKey {
        (&sk).into()
    }
}

#[cfg(feature = "arithmetic")]
impl<C> From<&SecretKey<C>> for JwkEcKey
where
    C: CurveArithmetic + JwkParameters,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    fn from(sk: &SecretKey<C>) -> JwkEcKey {
        let mut jwk = sk.public_key().to_jwk();
        let mut d = sk.to_bytes();
        jwk.d = Some(Base64Url::encode_string(&d));
        d.zeroize();
        jwk
    }
}

#[cfg(feature = "arithmetic")]
impl<C> TryFrom<JwkEcKey> for PublicKey<C>
where
    C: CurveArithmetic + JwkParameters,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    type Error = Error;

    fn try_from(jwk: JwkEcKey) -> Result<PublicKey<C>> {
        (&jwk).try_into()
    }
}

#[cfg(feature = "arithmetic")]
impl<C> TryFrom<&JwkEcKey> for PublicKey<C>
where
    C: CurveArithmetic + JwkParameters,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    type Error = Error;

    fn try_from(jwk: &JwkEcKey) -> Result<PublicKey<C>> {
        PublicKey::from_sec1_bytes(jwk.to_encoded_point::<C>()?.as_bytes())
    }
}

#[cfg(feature = "arithmetic")]
impl<C> From<PublicKey<C>> for JwkEcKey
where
    C: CurveArithmetic + JwkParameters,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    fn from(pk: PublicKey<C>) -> JwkEcKey {
        (&pk).into()
    }
}

#[cfg(feature = "arithmetic")]
impl<C> From<&PublicKey<C>> for JwkEcKey
where
    C: CurveArithmetic + JwkParameters,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    fn from(pk: &PublicKey<C>) -> JwkEcKey {
        Self::from_encoded_point::<C>(&pk.to_encoded_point(false)).expect("JWK encoding error")
    }
}

impl Debug for JwkEcKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let d = if self.d.is_some() {
            "Some(...)"
        } else {
            "None"
        };

        // NOTE: this implementation omits the `d` private key parameter
        f.debug_struct(JWK_TYPE_NAME)
            .field("crv", &self.crv)
            .field("x", &self.x)
            .field("y", &self.y)
            .field("d", &d)
            .finish()
    }
}

impl PartialEq for JwkEcKey {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;

        // Compare private key in constant time
        let d_eq = match &self.d {
            Some(d1) => match &other.d {
                Some(d2) => d1.as_bytes().ct_eq(d2.as_bytes()).into(),
                None => other.d.is_none(),
            },
            None => other.d.is_none(),
        };

        self.crv == other.crv && self.x == other.x && self.y == other.y && d_eq
    }
}

impl Eq for JwkEcKey {}

impl ZeroizeOnDrop for JwkEcKey {}

impl Drop for JwkEcKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for JwkEcKey {
    fn zeroize(&mut self) {
        if let Some(d) = &mut self.d {
            d.zeroize();
        }
    }
}

/// Decode a Base64url-encoded field element
fn decode_base64url_fe<C: Curve>(s: &str) -> Result<FieldBytes<C>> {
    let mut result = FieldBytes::<C>::default();
    Base64Url::decode(s, &mut result).map_err(|_| Error)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    #[cfg(feature = "dev")]
    use crate::dev::MockCurve;

    /// Example private key. From RFC 7518 Appendix C:
    /// <https://tools.ietf.org/html/rfc7518#appendix-C>
    const JWK_PRIVATE_KEY: &str = r#"
        {
          "kty":"EC",
          "crv":"P-256",
          "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
          "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
          "d":"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"
        }
    "#;

    /// Example public key.
    const JWK_PUBLIC_KEY: &str = r#"
        {
          "kty":"EC",
          "crv":"P-256",
          "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
          "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"
        }
    "#;

    const JWK_PUBLIC_KEY_THUMBPRINT: &str = "_GK0r6GCoJt9zcssg9lay4obIxgCq05ntiRymRHADSU";

    /// Example public key with an optional field.
    const JWK_PUBLIC_KEY_OPTIONAL_FIELD: &str = r#"
        {
          "kty":"EC",
          "crv":"P-256",
          "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
          "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
          "alg": "ES512"
        }
    "#;

    /// Example public key with an unknown field.
    const JWK_PUBLIC_KEY_UNKNOWN_FIELD: &str = r#"
        {
          "kty":"EC",
          "crv":"P-256",
          "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
          "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
          "foo": "bar"
        }
    "#;

    /// Example unsupported JWK (RSA key)
    const UNSUPPORTED_JWK: &str = r#"
        {
          "kty":"RSA",
          "kid":"cc34c0a0-bd5a-4a3c-a50d-a2a7db7643df",
          "use":"sig",
          "n":"pjdss8ZaDfEH6K6U7GeW2nxDqR4IP049fk1fK0lndimbMMVBdPv_hSpm8T8EtBDxrUdi1OHZfMhUixGaut-3nQ4GG9nM249oxhCtxqqNvEXrmQRGqczyLxuh-fKn9Fg--hS9UpazHpfVAFnB5aCfXoNhPuI8oByyFKMKaOVgHNqP5NBEqabiLftZD3W_lsFCPGuzr4Vp0YS7zS2hDYScC2oOMu4rGU1LcMZf39p3153Cq7bS2Xh6Y-vw5pwzFYZdjQxDn8x8BG3fJ6j8TGLXQsbKH1218_HcUJRvMwdpbUQG5nvA2GXVqLqdwp054Lzk9_B_f1lVrmOKuHjTNHq48w",
          "e":"AQAB",
          "d":"ksDmucdMJXkFGZxiomNHnroOZxe8AmDLDGO1vhs-POa5PZM7mtUPonxwjVmthmpbZzla-kg55OFfO7YcXhg-Hm2OWTKwm73_rLh3JavaHjvBqsVKuorX3V3RYkSro6HyYIzFJ1Ek7sLxbjDRcDOj4ievSX0oN9l-JZhaDYlPlci5uJsoqro_YrE0PRRWVhtGynd-_aWgQv1YzkfZuMD-hJtDi1Im2humOWxA4eZrFs9eG-whXcOvaSwO4sSGbS99ecQZHM2TcdXeAs1PvjVgQ_dKnZlGN3lTWoWfQP55Z7Tgt8Nf1q4ZAKd-NlMe-7iqCFfsnFwXjSiaOa2CRGZn-Q",
          "p":"4A5nU4ahEww7B65yuzmGeCUUi8ikWzv1C81pSyUKvKzu8CX41hp9J6oRaLGesKImYiuVQK47FhZ--wwfpRwHvSxtNU9qXb8ewo-BvadyO1eVrIk4tNV543QlSe7pQAoJGkxCia5rfznAE3InKF4JvIlchyqs0RQ8wx7lULqwnn0",
          "q":"ven83GM6SfrmO-TBHbjTk6JhP_3CMsIvmSdo4KrbQNvp4vHO3w1_0zJ3URkmkYGhz2tgPlfd7v1l2I6QkIh4Bumdj6FyFZEBpxjE4MpfdNVcNINvVj87cLyTRmIcaGxmfylY7QErP8GFA-k4UoH_eQmGKGK44TRzYj5hZYGWIC8",
          "dp":"lmmU_AG5SGxBhJqb8wxfNXDPJjf__i92BgJT2Vp4pskBbr5PGoyV0HbfUQVMnw977RONEurkR6O6gxZUeCclGt4kQlGZ-m0_XSWx13v9t9DIbheAtgVJ2mQyVDvK4m7aRYlEceFh0PsX8vYDS5o1txgPwb3oXkPTtrmbAGMUBpE",
          "dq":"mxRTU3QDyR2EnCv0Nl0TCF90oliJGAHR9HJmBe__EjuCBbwHfcT8OG3hWOv8vpzokQPRl5cQt3NckzX3fs6xlJN4Ai2Hh2zduKFVQ2p-AF2p6Yfahscjtq-GY9cB85NxLy2IXCC0PF--Sq9LOrTE9QV988SJy_yUrAjcZ5MmECk",
          "qi":"ldHXIrEmMZVaNwGzDF9WG8sHj2mOZmQpw9yrjLK9hAsmsNr5LTyqWAqJIYZSwPTYWhY4nu2O0EY9G9uYiqewXfCKw_UngrJt8Xwfq1Zruz0YY869zPN4GiE9-9rzdZB33RBw8kIOquY3MK74FMwCihYx_LiU2YTHkaoJ3ncvtvg"
        }
    "#;

    #[test]
    fn parse_private_key() {
        let jwk = JwkEcKey::from_str(JWK_PRIVATE_KEY).unwrap();
        assert_eq!(jwk.crv, "P-256");
        assert_eq!(jwk.x, "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0");
        assert_eq!(jwk.y, "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps");
        assert_eq!(
            jwk.d.as_ref().unwrap(),
            "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"
        );
    }

    #[test]
    fn parse_public_key() {
        let jwk = JwkEcKey::from_str(JWK_PUBLIC_KEY).unwrap();
        assert_eq!(jwk.crv, "P-256");
        assert_eq!(jwk.x, "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0");
        assert_eq!(jwk.y, "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps");
        assert_eq!(jwk.d, None);
    }

    #[test]
    fn parse_unsupported() {
        assert_eq!(JwkEcKey::from_str(UNSUPPORTED_JWK), Err(Error));
    }

    #[test]
    fn serialize_private_key() {
        let actual = JwkEcKey::from_str(JWK_PRIVATE_KEY).unwrap().to_string();
        let actual: alloc::collections::BTreeMap<String, String> =
            serde_json::from_str(&actual).unwrap();
        let expected: alloc::collections::BTreeMap<String, String> =
            serde_json::from_str(JWK_PRIVATE_KEY).unwrap();
        assert_eq!(actual.get("kty").unwrap(), expected.get("kty").unwrap());
        assert_eq!(actual.get("crv").unwrap(), expected.get("crv").unwrap());
        assert_eq!(actual.get("x").unwrap(), expected.get("x").unwrap());
        assert_eq!(actual.get("y").unwrap(), expected.get("y").unwrap());
        assert_eq!(actual.get("d").unwrap(), expected.get("d").unwrap());
    }

    #[test]
    fn serialize_public_key() {
        let actual = JwkEcKey::from_str(JWK_PUBLIC_KEY).unwrap().to_string();
        let actual: alloc::collections::BTreeMap<String, String> =
            serde_json::from_str(&actual).unwrap();
        let expected: alloc::collections::BTreeMap<String, String> =
            serde_json::from_str(JWK_PUBLIC_KEY).unwrap();
        assert_eq!(actual.get("kty").unwrap(), expected.get("kty").unwrap());
        assert_eq!(actual.get("crv").unwrap(), expected.get("crv").unwrap());
        assert_eq!(actual.get("x").unwrap(), expected.get("x").unwrap());
        assert_eq!(actual.get("y").unwrap(), expected.get("y").unwrap());
    }

    #[test]
    fn serialize_public_key_optional_field() {
        let actual = JwkEcKey::from_str(JWK_PUBLIC_KEY_OPTIONAL_FIELD)
            .unwrap()
            .to_string();
        let actual: alloc::collections::BTreeMap<String, String> =
            serde_json::from_str(&actual).unwrap();
        let expected: alloc::collections::BTreeMap<String, String> =
            serde_json::from_str(JWK_PUBLIC_KEY_OPTIONAL_FIELD).unwrap();
        assert_eq!(actual.get("kty").unwrap(), expected.get("kty").unwrap());
        assert_eq!(actual.get("crv").unwrap(), expected.get("crv").unwrap());
        assert_eq!(actual.get("x").unwrap(), expected.get("x").unwrap());
        assert_eq!(actual.get("y").unwrap(), expected.get("y").unwrap());
        assert_eq!(actual.get("alg").unwrap(), expected.get("alg").unwrap());
    }

    #[test]
    fn serialize_public_key_unknown_field() {
        let actual = JwkEcKey::from_str(JWK_PUBLIC_KEY_UNKNOWN_FIELD)
            .unwrap()
            .to_string();
        let actual: alloc::collections::BTreeMap<String, String> =
            serde_json::from_str(&actual).unwrap();
        let expected: alloc::collections::BTreeMap<String, String> =
            serde_json::from_str(JWK_PUBLIC_KEY_UNKNOWN_FIELD).unwrap();
        assert_eq!(actual.get("kty").unwrap(), expected.get("kty").unwrap());
        assert_eq!(actual.get("crv").unwrap(), expected.get("crv").unwrap());
        assert_eq!(actual.get("x").unwrap(), expected.get("x").unwrap());
        assert_eq!(actual.get("y").unwrap(), expected.get("y").unwrap());
    }

    #[test]
    fn calculate_jwk_thumbprint() {
        let jwk = JwkEcKey::from_str(JWK_PUBLIC_KEY).unwrap();
        let actual = jwk.thumbprint().unwrap();
        assert_eq!(&actual, JWK_PUBLIC_KEY_THUMBPRINT);
    }

    #[cfg(feature = "dev")]
    #[test]
    fn jwk_into_encoded_point() {
        let jwk = JwkEcKey::from_str(JWK_PUBLIC_KEY).unwrap();
        let point = jwk.to_encoded_point::<MockCurve>().unwrap();
        let (x, y) = match point.coordinates() {
            Coordinates::Uncompressed { x, y } => (x, y),
            other => panic!("unexpected coordinates: {other:?}"),
        };

        assert_eq!(&decode_base64url_fe::<MockCurve>(&jwk.x).unwrap(), x);
        assert_eq!(&decode_base64url_fe::<MockCurve>(&jwk.y).unwrap(), y);
    }

    #[cfg(feature = "dev")]
    #[test]
    fn encoded_point_into_jwk() {
        let jwk = JwkEcKey::from_str(JWK_PUBLIC_KEY).unwrap();
        let point = jwk.to_encoded_point::<MockCurve>().unwrap();
        let jwk2 = JwkEcKey::from_encoded_point::<MockCurve>(&point).unwrap();
        assert_eq!(jwk, jwk2);
    }
}
