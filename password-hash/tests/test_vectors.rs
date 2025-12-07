//! Test vectors for commonly used password hashing algorithms.

use password_hash::phc::{Ident, PasswordHash};

const ARGON2D_HASH: &str =
    "$argon2d$v=19$m=512,t=3,p=2$5VtWOO3cGWYQHEMaYGbsfQ$AcmqasQgW/wI6wAHAMk4aQ";
const SCRYPT_HASH: &str =
    "$scrypt$epIxT/h6HbbwHaehFnh/bw$7H0vsXlY8UxxyW/BWx/9GuY7jEvGjT71GFd6O4SZND0";

#[test]
fn argon2id() {
    let ph = PasswordHash::new(ARGON2D_HASH).unwrap();
    assert_eq!(ph.algorithm, Ident::new("argon2d").unwrap());
    assert_eq!(ph.version, Some(19));
    assert_eq!(ph.params.iter().count(), 3);
    assert_eq!(ph.params.get_decimal("m").unwrap(), 512);
    assert_eq!(ph.params.get_decimal("t").unwrap(), 3);
    assert_eq!(ph.params.get_decimal("p").unwrap(), 2);
    assert_eq!(
        ph.salt.unwrap().as_ref(),
        &[
            0xe5, 0x5b, 0x56, 0x38, 0xed, 0xdc, 0x19, 0x66, 0x10, 0x1c, 0x43, 0x1a, 0x60, 0x66,
            0xec, 0x7d
        ]
    );
    assert_eq!(ph.hash.unwrap().to_string(), "AcmqasQgW/wI6wAHAMk4aQ");
    assert_eq!(ph.to_string(), ARGON2D_HASH);
}

#[test]
fn scrypt() {
    let ph = PasswordHash::new(SCRYPT_HASH).unwrap();
    assert_eq!(ph.algorithm, Ident::new("scrypt").unwrap());
    assert_eq!(ph.version, None);
    assert_eq!(ph.params.len(), 0);
    assert_eq!(ph.salt.unwrap().to_string(), "epIxT/h6HbbwHaehFnh/bw");
    assert_eq!(
        ph.hash.unwrap().to_string(),
        "7H0vsXlY8UxxyW/BWx/9GuY7jEvGjT71GFd6O4SZND0"
    );
    assert_eq!(ph.to_string(), SCRYPT_HASH);
}
