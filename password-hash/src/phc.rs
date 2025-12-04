//! Password Hashing Competition string format implementation.

mod ident;
mod output;
mod params;
mod salt;
mod value;

use crate::{Error, PasswordHasher, PasswordVerifier};
pub use ident::Ident;
pub use output::Output;
pub use params::ParamsString;
pub use salt::{Salt, SaltString};
pub use value::{Decimal, Value};

use core::fmt;

#[cfg(feature = "alloc")]
use alloc::{
    str::FromStr,
    string::{String, ToString},
};

/// Separator character used in password hashes (e.g. `$6$...`).
const PASSWORD_HASH_SEPARATOR: char = '$';

/// Password hash.
///
/// This type corresponds to the parsed representation of a PHC string as
/// described in the [PHC string format specification][1].
///
/// PHC strings have the following format:
///
/// ```text
/// $<id>[$v=<version>][$<param>=<value>(,<param>=<value>)*][$<salt>[$<hash>]]
/// ```
///
/// where:
///
/// - `<id>` is the symbolic name for the function
/// - `<version>` is the algorithm version
/// - `<param>` is a parameter name
/// - `<value>` is a parameter value
/// - `<salt>` is an encoding of the salt
/// - `<hash>` is an encoding of the hash output
///
/// The string is then the concatenation, in that order, of:
///
/// - a `$` sign;
/// - the function symbolic name;
/// - optionally, a `$` sign followed by the algorithm version with a `v=version` format;
/// - optionally, a `$` sign followed by one or several parameters, each with a `name=value` format;
///   the parameters are separated by commas;
/// - optionally, a `$` sign followed by the (encoded) salt value;
/// - optionally, a `$` sign followed by the (encoded) hash output (the hash output may be present
///   only if the salt is present).
///
/// [1]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#specification
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordHash<'a> {
    /// Password hashing algorithm identifier.
    ///
    /// This corresponds to the `<id>` field in a PHC string, a.k.a. the
    /// symbolic name for the function.
    pub algorithm: Ident<'a>,

    /// Optional version field.
    ///
    /// This corresponds to the `<version>` field in a PHC string.
    pub version: Option<Decimal>,

    /// Algorithm-specific parameters.
    ///
    /// This corresponds to the set of `$<param>=<value>(,<param>=<value>)*`
    /// name/value pairs in a PHC string.
    pub params: ParamsString,

    /// [`Salt`] string for personalizing a password hash output.
    ///
    /// This corresponds to the `<salt>` value in a PHC string.
    pub salt: Option<Salt<'a>>,

    /// Password hashing function [`Output`], a.k.a. hash/digest.
    ///
    /// This corresponds to the `<hash>` output in a PHC string.
    pub hash: Option<Output>,
}

impl<'a> PasswordHash<'a> {
    /// Parse a password hash from a string in the PHC string format.
    pub fn new(s: &'a str) -> crate::Result<Self> {
        if s.is_empty() {
            return Err(Error::PhcStringField);
        }

        let mut fields = s.split(PASSWORD_HASH_SEPARATOR);
        let beginning = fields.next().expect("no first field");

        if beginning.chars().next().is_some() {
            return Err(Error::PhcStringField);
        }

        let algorithm = fields
            .next()
            .ok_or(Error::PhcStringField)
            .and_then(Ident::try_from)?;

        let mut version = None;
        let mut params = ParamsString::new();
        let mut salt = None;
        let mut hash = None;

        let mut next_field = fields.next();

        if let Some(field) = next_field {
            // v=<version>
            if field.starts_with("v=") && !field.contains(params::PARAMS_DELIMITER) {
                version = Some(Value::new(&field[2..]).and_then(|value| value.decimal())?);
                next_field = None;
            }
        }

        if next_field.is_none() {
            next_field = fields.next();
        }

        if let Some(field) = next_field {
            // <param>=<value>
            if field.contains(params::PAIR_DELIMITER) {
                params = field.parse()?;
                next_field = None;
            }
        }

        if next_field.is_none() {
            next_field = fields.next();
        }

        if let Some(s) = next_field {
            salt = Some(s.try_into()?);
        }

        if let Some(field) = fields.next() {
            hash = Some(Output::decode(field)?);
        }

        if fields.next().is_some() {
            return Err(Error::PhcStringTrailingData);
        }

        Ok(Self {
            algorithm,
            version,
            params,
            salt,
            hash,
        })
    }

    /// Generate a password hash using the supplied algorithm.
    pub fn generate(
        phf: impl PasswordHasher,
        password: impl AsRef<[u8]>,
        salt: impl Into<Salt<'a>>,
    ) -> crate::Result<Self> {
        phf.hash_password(password.as_ref(), salt)
    }

    /// Verify this password hash using the specified set of supported
    /// [`PasswordHasher`] trait objects.
    pub fn verify_password(
        &self,
        phfs: &[&dyn PasswordVerifier],
        password: impl AsRef<[u8]>,
    ) -> crate::Result<()> {
        for &phf in phfs {
            if phf.verify_password(password.as_ref(), self).is_ok() {
                return Ok(());
            }
        }

        Err(Error::Password)
    }

    /// Serialize this [`PasswordHash`] as a [`PasswordHashString`].
    #[cfg(feature = "alloc")]
    pub fn serialize(&self) -> PasswordHashString {
        self.into()
    }
}

// Note: this uses `TryFrom` instead of `FromStr` to support a lifetime on
// the `str` the value is being parsed from.
impl<'a> TryFrom<&'a str> for PasswordHash<'a> {
    type Error = Error;

    fn try_from(s: &'a str) -> crate::Result<Self> {
        Self::new(s)
    }
}

impl fmt::Display for PasswordHash<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", PASSWORD_HASH_SEPARATOR, self.algorithm)?;

        if let Some(version) = self.version {
            write!(f, "{PASSWORD_HASH_SEPARATOR}v={version}")?;
        }

        if !self.params.is_empty() {
            write!(f, "{}{}", PASSWORD_HASH_SEPARATOR, self.params)?;
        }

        if let Some(salt) = &self.salt {
            write!(f, "{PASSWORD_HASH_SEPARATOR}{salt}")?;

            if let Some(hash) = &self.hash {
                write!(f, "{PASSWORD_HASH_SEPARATOR}{hash}")?;
            }
        }

        Ok(())
    }
}

/// Serialized [`PasswordHash`].
///
/// This type contains a serialized password hash string which is ensured to
/// parse successfully.
// TODO(tarcieri): cached parsed representations? or at least structural data
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordHashString {
    /// String value
    string: String,
}

#[cfg(feature = "alloc")]
#[allow(clippy::len_without_is_empty)]
impl PasswordHashString {
    /// Parse a password hash from a string in the PHC string format.
    pub fn new(s: &str) -> crate::Result<Self> {
        PasswordHash::new(s).map(Into::into)
    }

    /// Parse this owned string as a [`PasswordHash`].
    pub fn password_hash(&self) -> PasswordHash<'_> {
        PasswordHash::new(&self.string).expect("malformed password hash")
    }

    /// Borrow this value as a `str`.
    pub fn as_str(&self) -> &str {
        self.string.as_str()
    }

    /// Borrow this value as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }

    /// Get the length of this value in ASCII characters.
    pub fn len(&self) -> usize {
        self.as_str().len()
    }

    /// Password hashing algorithm identifier.
    pub fn algorithm(&self) -> Ident<'_> {
        self.password_hash().algorithm
    }

    /// Optional version field.
    pub fn version(&self) -> Option<Decimal> {
        self.password_hash().version
    }

    /// Algorithm-specific parameters.
    pub fn params(&self) -> ParamsString {
        self.password_hash().params
    }

    /// [`Salt`] string for personalizing a password hash output.
    pub fn salt(&self) -> Option<Salt<'_>> {
        self.password_hash().salt
    }

    /// Password hashing function [`Output`], a.k.a. hash/digest.
    pub fn hash(&self) -> Option<Output> {
        self.password_hash().hash
    }
}

#[cfg(feature = "alloc")]
impl AsRef<str> for PasswordHashString {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[cfg(feature = "alloc")]
impl From<PasswordHash<'_>> for PasswordHashString {
    fn from(hash: PasswordHash<'_>) -> PasswordHashString {
        PasswordHashString::from(&hash)
    }
}

#[cfg(feature = "alloc")]
impl From<&PasswordHash<'_>> for PasswordHashString {
    fn from(hash: &PasswordHash<'_>) -> PasswordHashString {
        PasswordHashString {
            string: hash.to_string(),
        }
    }
}

#[cfg(feature = "alloc")]
impl FromStr for PasswordHashString {
    type Err = Error;

    fn from_str(s: &str) -> crate::Result<Self> {
        Self::new(s)
    }
}

#[cfg(feature = "alloc")]
impl fmt::Display for PasswordHashString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
