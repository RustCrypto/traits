//! Password hashing tests

#![cfg(feature = "phc")]

use core::{fmt::Display, str::FromStr};
use password_hash::{CustomizedPasswordHasher, Error, PasswordHasher, Result};
use phc::{Decimal, Ident, Output, ParamsString, PasswordHash, Salt};

const ALG: Ident = Ident::new_unwrap("example");

/// Stub password hashing function for testing.
pub struct StubPasswordHasher;

impl CustomizedPasswordHasher<PasswordHash> for StubPasswordHasher {
    type Params = StubParams;

    fn hash_password_customized(
        &self,
        password: &[u8],
        salt: &[u8],
        algorithm: Option<&str>,
        version: Option<Decimal>,
        params: StubParams,
    ) -> Result<PasswordHash> {
        let salt = Salt::new(salt).map_err(|_| Error::SaltInvalid)?;
        let mut output = Vec::new();

        if let Some(alg) = algorithm {
            if Ident::new(alg).map_err(|_| Error::Algorithm)? != ALG {
                return Err(Error::Algorithm);
            }
        }

        for slice in &[b"pw", password, b",salt:", salt.as_ref()] {
            output.extend_from_slice(slice);
        }

        let hash = Output::new(&output).map_err(|_| Error::OutputSize)?;

        Ok(PasswordHash {
            algorithm: ALG,
            version,
            params: params.try_into()?,
            salt: Some(salt),
            hash: Some(hash),
        })
    }
}

impl PasswordHasher<PasswordHash> for StubPasswordHasher {
    fn hash_password_with_salt(&self, password: &[u8], salt: &[u8]) -> Result<PasswordHash> {
        self.hash_password_customized(password, salt, None, None, StubParams)
    }
}

/// Stub parameters
#[derive(Clone, Debug, Default)]
pub struct StubParams;

impl Display for StubParams {
    fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Ok(())
    }
}

impl FromStr for StubParams {
    type Err = Error;

    fn from_str(_: &str) -> Result<Self> {
        Ok(Self)
    }
}

impl TryFrom<StubParams> for ParamsString {
    type Error = Error;

    fn try_from(_: StubParams) -> Result<Self> {
        Ok(Self::default())
    }
}

#[test]
fn verify_password_hash() {
    let valid_password = b"test password";
    let salt = Salt::from_b64("testsalt000").unwrap();
    let hash = StubPasswordHasher
        .hash_password_with_salt(valid_password, &salt)
        .unwrap();

    // Sanity tests for StubFunction impl above
    assert_eq!(hash.algorithm, ALG);
    assert_eq!(
        hash.salt.unwrap().as_ref(),
        &[0xb5, 0xeb, 0x2d, 0xb1, 0xa9, 0x6d, 0xd3, 0x4d]
    );
}
