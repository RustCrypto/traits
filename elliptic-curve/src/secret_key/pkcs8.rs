//! PKCS#8 encoding/decoding support.

use super::SecretKey;
use crate::{
    pkcs8::{self, der::Decode, AssociatedOid, DecodePrivateKey},
    sec1::{ModulusSize, ValidatePublicKey},
    Curve, FieldSize, ALGORITHM_OID,
};
use sec1::EcPrivateKey;

// Imports for the `EncodePrivateKey` impl
#[cfg(all(feature = "alloc", feature = "arithmetic"))]
use {
    crate::{
        sec1::{FromEncodedPoint, ToEncodedPoint},
        AffinePoint, ProjectiveArithmetic,
    },
    pkcs8::{der, EncodePrivateKey},
};

// Imports for actual PEM support
#[cfg(feature = "pem")]
use {
    crate::{error::Error, Result},
    core::str::FromStr,
};

impl<C> TryFrom<pkcs8::PrivateKeyInfo<'_>> for SecretKey<C>
where
    C: Curve + AssociatedOid + ValidatePublicKey,
    FieldSize<C>: ModulusSize,
{
    type Error = pkcs8::Error;

    fn try_from(private_key_info: pkcs8::PrivateKeyInfo<'_>) -> pkcs8::Result<Self> {
        private_key_info
            .algorithm
            .assert_oids(ALGORITHM_OID, C::OID)?;

        let ec_private_key = EcPrivateKey::from_der(private_key_info.private_key)?;
        Ok(Self::try_from(ec_private_key)?)
    }
}

impl<C> DecodePrivateKey for SecretKey<C>
where
    C: Curve + AssociatedOid + ValidatePublicKey,
    FieldSize<C>: ModulusSize,
{
}

#[cfg(all(feature = "alloc", feature = "arithmetic"))]
impl<C> EncodePrivateKey for SecretKey<C>
where
    C: Curve + AssociatedOid + ProjectiveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: ModulusSize,
{
    fn to_pkcs8_der(&self) -> pkcs8::Result<der::SecretDocument> {
        let algorithm_identifier = pkcs8::AlgorithmIdentifier {
            oid: ALGORITHM_OID,
            parameters: Some((&C::OID).into()),
        };

        let ec_private_key = self.to_sec1_der()?;
        let pkcs8_key = pkcs8::PrivateKeyInfo::new(algorithm_identifier, &ec_private_key);
        Ok(der::SecretDocument::encode_msg(&pkcs8_key)?)
    }
}

#[cfg(feature = "pem")]
impl<C> FromStr for SecretKey<C>
where
    C: Curve + AssociatedOid + ValidatePublicKey,
    FieldSize<C>: ModulusSize,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_pkcs8_pem(s).map_err(|_| Error)
    }
}
