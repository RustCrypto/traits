//! Password hashing tests

use core::{fmt::Display, str::FromStr};
use password_hash::PasswordHasher;
pub use password_hash::{
    CustomizedPasswordHasher,
    errors::{Error, Result},
    phc::{Decimal, Ident, Output, ParamsString, PasswordHash, Salt},
};

const ALG: Ident = Ident::new_unwrap("example");

/// Stub password hashing function for testing.
pub struct StubPasswordHasher;

impl PasswordHasher for StubPasswordHasher {
    fn hash_password<'a>(&self, password: &[u8], salt: &'a str) -> Result<PasswordHash<'a>> {
        self.hash_password_customized(password, None, None, StubParams, salt)
    }
}

impl CustomizedPasswordHasher for StubPasswordHasher {
    type Params = StubParams;

    fn hash_password_customized<'a>(
        &self,
        password: &[u8],
        algorithm: Option<&'a str>,
        version: Option<Decimal>,
        params: StubParams,
        salt: &'a str,
    ) -> Result<PasswordHash<'a>> {
        let salt = Salt::from_b64(salt)?;
        let mut output = Vec::new();

        if let Some(alg) = algorithm {
            if Ident::new(alg)? != ALG {
                return Err(Error::Algorithm);
            }
        }

        for slice in &[b"pw", password, b",salt:", salt.as_str().as_bytes()] {
            output.extend_from_slice(slice);
        }

        let hash = Output::new(&output)?;

        Ok(PasswordHash {
            algorithm: ALG,
            version,
            params: params.try_into()?,
            salt: Some(salt),
            hash: Some(hash),
        })
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
    let valid_password = "test password";
    let salt = "test-salt";
    let hash = PasswordHash::generate(StubPasswordHasher, valid_password, salt).unwrap();

    // Sanity tests for StubFunction impl above
    assert_eq!(hash.algorithm, ALG);
    assert_eq!(hash.salt.unwrap().as_str(), salt);

    // Tests for generic password verification logic
    assert_eq!(
        hash.verify_password(&[&StubPasswordHasher], valid_password),
        Ok(())
    );

    assert_eq!(
        hash.verify_password(&[&StubPasswordHasher], "wrong password"),
        Err(Error::Password)
    );
}
