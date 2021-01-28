//! Password hashing tests

pub use password_hash::{
    Decimal, HasherError, Ident, Output, ParamsString, PasswordHash, PasswordHasher, Salt,
    VerifyError,
};
use std::convert::{TryFrom, TryInto};

const ALG: Ident = Ident::new("example");

/// Stub password hashing function for testing.
pub struct StubPasswordHasher;

impl PasswordHasher for StubPasswordHasher {
    type Params = StubParams;

    fn hash_password<'a>(
        &self,
        password: &[u8],
        algorithm: Option<Ident<'a>>,
        _version: Option<Decimal>,
        params: StubParams,
        salt: Salt<'a>,
    ) -> Result<PasswordHash<'a>, HasherError> {
        let mut output = Vec::new();

        if let Some(alg) = algorithm {
            if alg != ALG {
                return Err(HasherError::Algorithm);
            }
        }

        for slice in &[b"pw", password, b",salt:", salt.as_bytes()] {
            output.extend_from_slice(slice);
        }

        let hash = Output::new(&output)?;

        Ok(PasswordHash {
            algorithm: ALG,
            version: None,
            params: params.try_into()?,
            salt: Some(salt),
            hash: Some(hash),
        })
    }
}

/// Stub parameters
#[derive(Clone, Debug, Default)]
pub struct StubParams;

impl<'a> TryFrom<&'a ParamsString> for StubParams {
    type Error = HasherError;

    fn try_from(_: &'a ParamsString) -> Result<Self, HasherError> {
        Ok(Self)
    }
}

impl<'a> TryFrom<StubParams> for ParamsString {
    type Error = HasherError;

    fn try_from(_: StubParams) -> Result<Self, HasherError> {
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
        Err(VerifyError)
    );
}
