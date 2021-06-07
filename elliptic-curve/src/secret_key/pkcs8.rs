//! PKCS#8 encoding/decoding support

use super::SecretKey;
use crate::{
    sec1::{self, UncompressedPointSize, UntaggedPointSize, ValidatePublicKey},
    weierstrass, AlgorithmParameters, ALGORITHM_OID,
};
use core::ops::Add;
use generic_array::{typenum::U1, ArrayLength};
use pkcs8::{
    der::{
        self,
        asn1::{BitString, ContextSpecific, OctetString},
        TagNumber,
    },
    FromPrivateKey,
};
use zeroize::Zeroize;

// Imports for the `ToPrivateKey` impl
// TODO(tarcieri): use weak activation of `pkcs8/alloc` for gating `ToPrivateKey` impl
#[cfg(all(feature = "arithmetic", feature = "pem"))]
use {
    crate::{
        scalar::Scalar,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        AffinePoint, ProjectiveArithmetic,
    },
    core::convert::TryInto,
    pkcs8::{der::Encodable, ToPrivateKey},
    zeroize::Zeroizing,
};

// Imports for actual PEM support
#[cfg(feature = "pem")]
use {
    crate::{error::Error, Result},
    core::str::FromStr,
};

/// Version
const VERSION: u8 = 1;

/// Context-specific tag number for the public key.
const PUBLIC_KEY_TAG: TagNumber = TagNumber::new(1);

#[cfg_attr(docsrs, doc(cfg(feature = "pkcs8")))]
impl<C> FromPrivateKey for SecretKey<C>
where
    C: weierstrass::Curve + AlgorithmParameters + ValidatePublicKey,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    fn from_pkcs8_private_key_info(
        private_key_info: pkcs8::PrivateKeyInfo<'_>,
    ) -> pkcs8::Result<Self> {
        private_key_info
            .algorithm
            .assert_oids(ALGORITHM_OID, C::OID)?;

        let mut decoder = der::Decoder::new(private_key_info.private_key);

        let result = decoder.sequence(|decoder| {
            if decoder.uint8()? != VERSION {
                return Err(der::Tag::Integer.value_error());
            }

            let secret_key = Self::from_bytes(decoder.octet_string()?)
                .map_err(|_| der::Tag::Sequence.value_error())?;

            let public_key = decoder
                .context_specific(PUBLIC_KEY_TAG)?
                .ok_or_else(|| der::Tag::ContextSpecific(PUBLIC_KEY_TAG).value_error())?
                .bit_string()?;

            if let Ok(pk) = sec1::EncodedPoint::<C>::from_bytes(public_key.as_ref()) {
                if C::validate_public_key(&secret_key, &pk).is_ok() {
                    return Ok(secret_key);
                }
            }

            Err(der::Tag::BitString.value_error())
        })?;

        Ok(decoder.finish(result)?)
    }
}

// TODO(tarcieri): use weak activation of `pkcs8/alloc` for this when possible
// It doesn't strictly depend on `pkcs8/pem` but we can't easily activate `pkcs8/alloc`
// without adding a separate crate feature just for this functionality.
#[cfg(all(feature = "arithmetic", feature = "pem"))]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
impl<C> ToPrivateKey for SecretKey<C>
where
    C: weierstrass::Curve + AlgorithmParameters + ProjectiveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    Scalar<C>: Zeroize,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    fn to_pkcs8_der(&self) -> pkcs8::Result<pkcs8::PrivateKeyDocument> {
        // TODO(tarcieri): wrap `secret_key_bytes` in `Zeroizing`
        let mut secret_key_bytes = self.to_bytes();
        let secret_key_field = OctetString::new(&secret_key_bytes)?;
        let public_key_bytes = self.public_key().to_encoded_point(false);
        let public_key_field = ContextSpecific {
            tag_number: PUBLIC_KEY_TAG,
            value: BitString::new(public_key_bytes.as_ref())?.into(),
        };

        let der_message_fields: &[&dyn Encodable] =
            &[&VERSION, &secret_key_field, &public_key_field];

        let encoded_len = der::message::encoded_len(der_message_fields)?.try_into()?;
        let mut der_message = Zeroizing::new(vec![0u8; encoded_len]);
        let mut encoder = der::Encoder::new(&mut der_message);
        encoder.message(der_message_fields)?;
        encoder.finish()?;

        // TODO(tarcieri): wrap `secret_key_bytes` in `Zeroizing`
        secret_key_bytes.zeroize();

        Ok(pkcs8::PrivateKeyInfo::new(C::algorithm_identifier(), &der_message).to_der())
    }
}

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
impl<C> FromStr for SecretKey<C>
where
    C: weierstrass::Curve + AlgorithmParameters + ValidatePublicKey,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_pkcs8_pem(s).map_err(|_| Error)
    }
}
