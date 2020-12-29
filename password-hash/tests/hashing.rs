/// Password hashing tests
pub use password_hash::{
    Algorithm, Ident, Output, Params, PasswordHash, PasswordHashingFunction, PhfError, Salt,
    VerifyError,
};

const ALG: Algorithm = Algorithm::Other(Ident::new("example"));

/// Stub password hashing function for testing.
pub struct StubFunction;

impl PasswordHashingFunction for StubFunction {
    fn hash_password(
        &self,
        algorithm: Option<Algorithm>,
        password: &[u8],
        salt: Salt,
        params: Params,
    ) -> Result<PasswordHash, PhfError> {
        let mut output = Vec::new();

        if let Some(alg) = algorithm {
            if alg != ALG {
                return Err(PhfError::Algorithm(alg));
            }
        }

        for slice in &[b"pw", password, b",salt:", salt.as_ref()] {
            output.extend_from_slice(slice);
        }

        let hash = Output::new(&output)?;

        Ok(PasswordHash {
            algorithm: ALG,
            params,
            salt: Some(salt),
            hash: Some(hash),
        })
    }
}

#[test]
fn verify_password_hash() {
    let valid_password = "test password";
    let salt = Salt::new(b"test salt").unwrap();
    let params = Params::new();
    let hash = PasswordHash::generate(StubFunction, valid_password, salt, params.clone()).unwrap();

    // Sanity tests for StubFunction impl above
    assert_eq!(hash.algorithm, ALG);
    assert_eq!(hash.salt.unwrap(), salt);
    assert_eq!(hash.params, params);

    // Tests for generic password verification logic
    assert_eq!(
        hash.verify_password(&[&StubFunction], valid_password),
        Ok(())
    );

    assert_eq!(
        hash.verify_password(&[&StubFunction], "wrong password"),
        Err(VerifyError)
    );
}
