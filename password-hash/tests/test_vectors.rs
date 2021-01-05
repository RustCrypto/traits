//! Test vectors for commonly used password hashing algorithms.

#![cfg(feature = "registry")]

use password_hash::{
    algorithm::{argon2, bcrypt},
    Algorithm, PasswordHash,
};

const ARGON2ID_HASH: &str =
    "$argon2id$m=65536,t=3,p=2$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";
const BCRYPT_HASH: &str = "$2b$MTIzNA$i5btSOiulHhaPHPbgNUGdObga/GCAVG/y5HHY1ra7L0C9dpCaw8u";
const SCRYPT_HASH: &str =
    "$scrypt$epIxT/h6HbbwHaehFnh/bw$7H0vsXlY8UxxyW/BWx/9GuY7jEvGjT71GFd6O4SZND0";

#[test]
fn argon2id() {
    let ph = ARGON2ID_HASH.parse::<PasswordHash>().unwrap();
    assert_eq!(ph.algorithm, Algorithm::Argon2(argon2::Variant::ID));
    assert_eq!(ph.params.len(), 3);
    assert_eq!(ph.params["m"], 65536.into());
    assert_eq!(ph.params["t"], 3.into());
    assert_eq!(ph.params["p"], 2.into());
    assert_eq!(ph.salt.unwrap().to_string(), "c29tZXNhbHQ");
    assert_eq!(
        ph.hash.unwrap().to_string(),
        "RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
    );
    assert_eq!(ph.to_string(), ARGON2ID_HASH);
}

#[test]
fn bcrypt() {
    let ph = BCRYPT_HASH.parse::<PasswordHash>().unwrap();
    assert_eq!(ph.algorithm, Algorithm::Bcrypt(bcrypt::Variant::B));
    assert_eq!(ph.params.len(), 0);
    assert_eq!(ph.salt.unwrap().to_string(), "MTIzNA");
    assert_eq!(
        ph.hash.unwrap().to_string(),
        "i5btSOiulHhaPHPbgNUGdObga/GCAVG/y5HHY1ra7L0C9dpCaw8u"
    );
    assert_eq!(ph.to_string(), BCRYPT_HASH);
}

#[test]
fn scrypt() {
    let ph = SCRYPT_HASH.parse::<PasswordHash>().unwrap();
    assert_eq!(ph.algorithm, Algorithm::Scrypt);
    assert_eq!(ph.params.len(), 0);
    assert_eq!(ph.salt.unwrap().to_string(), "epIxT/h6HbbwHaehFnh/bw");
    assert_eq!(
        ph.hash.unwrap().to_string(),
        "7H0vsXlY8UxxyW/BWx/9GuY7jEvGjT71GFd6O4SZND0"
    );
    assert_eq!(ph.to_string(), SCRYPT_HASH);
}
