//! SEC1 elliptic curve private key support.
//!
//! Support for ASN.1 DER-encoded elliptic curve private keys as described in
//! SEC1: Elliptic Curve Cryptography (Version 2.0) Appendix C.4 (p.108):
//!
//! <https://www.secg.org/sec1-v2.pdf>

use core::{
    convert::{TryFrom, TryInto},
    fmt,
};
use der::{
    asn1::{Any, BitString, ContextSpecific, ObjectIdentifier, OctetString},
    Choice, Encodable, Encoder, Length, Message, Tag, TagNumber,
};

/// `ECPrivateKey` version.
///
/// From RFC5913 Section 3:
/// > version specifies the syntax version number of the elliptic curve
/// > private key structure.  For this version of the document, it SHALL
/// > be set to ecPrivkeyVer1, which is of type INTEGER and whose value
/// > is one (1).
const VERSION: u8 = 1;

/// Context-specific tag number for the elliptic curve parameters.
const EC_PARAMETERS_TAG: TagNumber = TagNumber::new(0);

/// Context-specific tag number for the public key.
const PUBLIC_KEY_TAG: TagNumber = TagNumber::new(1);

/// SEC1 elliptic curve private key.
///
/// Described in [SEC1: Elliptic Curve Cryptography (Version 2.0)]
/// Appendix C.4 (p.108) and also [RFC5915 Section 3]:
///
/// ```text
/// ECPrivateKey ::= SEQUENCE {
///   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
///   privateKey     OCTET STRING,
///   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
///   publicKey  [1] BIT STRING OPTIONAL
/// }
/// ```
///
/// This ASN.1 structure is used for PKCS#8 private keys. It can also be used
/// directly, with a PEM encoding that begins with the following:
///
/// ```text
/// -----BEGIN EC PRIVATE KEY-----
/// ```
///
/// [SEC1: Elliptic Curve Cryptography (Version 2.0)]: https://www.secg.org/sec1-v2.pdf
/// [RFC5915 Section 3]: https://datatracker.ietf.org/doc/html/rfc5915#section-3
#[derive(Clone)]
pub struct EcPrivateKey<'a> {
    /// Private key data.
    pub private_key: &'a [u8],

    /// Elliptic curve parameters.
    pub parameters: Option<EcParameters>,

    /// Public key data, optionally available if version is V2.
    pub public_key: Option<&'a [u8]>,
}

impl<'a> TryFrom<Any<'a>> for EcPrivateKey<'a> {
    type Error = der::Error;

    fn try_from(any: Any<'a>) -> der::Result<EcPrivateKey<'a>> {
        any.sequence(|decoder| {
            if decoder.uint8()? != VERSION {
                return Err(der::Tag::Integer.value_error());
            }

            let private_key = decoder.octet_string()?.as_bytes();

            let parameters = decoder
                .context_specific(EC_PARAMETERS_TAG)?
                .map(TryInto::try_into)
                .transpose()?;

            let public_key = decoder
                .context_specific(PUBLIC_KEY_TAG)?
                .map(|any| any.bit_string())
                .transpose()?
                .map(|bs| bs.as_bytes());

            Ok(EcPrivateKey {
                private_key,
                parameters,
                public_key,
            })
        })
    }
}

impl<'a> Message<'a> for EcPrivateKey<'a> {
    fn fields<F, T>(&self, f: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        f(&[
            &VERSION,
            &OctetString::new(self.private_key)?,
            &self.parameters.as_ref().map(|params| ContextSpecific {
                tag_number: EC_PARAMETERS_TAG,
                value: params.into(),
            }),
            &self
                .public_key
                .map(|pk| {
                    BitString::new(pk).map(|value| ContextSpecific {
                        tag_number: PUBLIC_KEY_TAG,
                        value: value.into(),
                    })
                })
                .transpose()?,
        ])
    }
}

impl<'a> fmt::Debug for EcPrivateKey<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcPrivateKey")
            .field("parameters", &self.parameters)
            .field("public_key", &self.public_key)
            .finish() // TODO: use `finish_non_exhaustive` when stable
    }
}

/// Elliptic curve parameters as described in
/// [RFC5480 Section 2.1.1](https://datatracker.ietf.org/doc/html/rfc5480#section-2.1.1):
///
/// ```text
/// ECParameters ::= CHOICE {
///   namedCurve         OBJECT IDENTIFIER
///   -- implicitCurve   NULL
///   -- specifiedCurve  SpecifiedECDomain
/// }
///   -- implicitCurve and specifiedCurve MUST NOT be used in PKIX.
///   -- Details for SpecifiedECDomain can be found in [X9.62].
///   -- Any future additions to this CHOICE should be coordinated
///   -- with ANSI X9.
/// ```
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum EcParameters {
    /// Elliptic curve named by a particular OID.
    ///
    /// > namedCurve identifies all the required values for a particular
    /// > set of elliptic curve domain parameters to be represented by an
    /// > object identifier.
    NamedCurve(ObjectIdentifier),
}

impl EcParameters {
    /// Obtain the `namedCurve` OID.
    pub fn named_curve(self) -> Option<ObjectIdentifier> {
        match self {
            Self::NamedCurve(oid) => Some(oid),
        }
    }
}

impl<'a> From<&'a EcParameters> for Any<'a> {
    fn from(params: &'a EcParameters) -> Any<'a> {
        match params {
            EcParameters::NamedCurve(oid) => oid.into(),
        }
    }
}

impl From<ObjectIdentifier> for EcParameters {
    fn from(oid: ObjectIdentifier) -> EcParameters {
        EcParameters::NamedCurve(oid)
    }
}

impl TryFrom<Any<'_>> for EcParameters {
    type Error = der::Error;

    fn try_from(any: Any<'_>) -> der::Result<EcParameters> {
        match any.tag() {
            Tag::ObjectIdentifier => any.oid().map(Self::NamedCurve),
            tag => Err(tag.unexpected_error(Some(Tag::ObjectIdentifier))),
        }
    }
}

impl Choice<'_> for EcParameters {
    fn can_decode(tag: Tag) -> bool {
        tag == Tag::ObjectIdentifier
    }
}

impl Encodable for EcParameters {
    fn encoded_len(&self) -> der::Result<Length> {
        match self {
            Self::NamedCurve(oid) => oid.encoded_len(),
        }
    }

    fn encode(&self, encoder: &mut Encoder<'_>) -> der::Result<()> {
        match self {
            Self::NamedCurve(oid) => encoder.oid(*oid),
        }
    }
}
