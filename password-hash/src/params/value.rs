//! Algorithm parameter value as defined by the [PHC string format].
//!
//! Implements the following parts of the specification:
//!
//! > The value for each parameter consists in characters in: `[a-zA-Z0-9/+.-]`
//! > (lowercase letters, uppercase letters, digits, /, +, . and -). No other
//! > character is allowed. Interpretation of the value depends on the
//! > parameter and the function. The function specification MUST unambiguously
//! > define the set of valid parameter values. The function specification MUST
//! > define a maximum length (in characters) for each parameter. For numerical
//! > parameters, functions SHOULD use plain decimal encoding (other encodings
//! > are possible as long as they are clearly defined).
//!
//! [1]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md

use crate::{
    b64,
    errors::{B64Error, ParseError},
};
use core::{convert::TryFrom, fmt, str};

/// Maximum size of a parameter value in ASCII characters.
const MAX_LENGTH: usize = 48;

/// Type used to represent decimal (i.e. integer) values.
pub type Decimal = i32;

/// Algorithm parameter value.
///
/// Provides an enum over [`Decimal`] and string (i.e. [`ValueStr`]) values
/// to allow ergonomically using and parsing integer values, which is the
/// main use case for this type.
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Value<'a> {
    /// Decimal value.
    Decimal(Decimal),

    /// String value.
    Str(ValueStr<'a>),
}

impl<'a> Value<'a> {
    /// Parse a [`Value`] from the provided `str`, validating it according to
    /// the PHC string format's rules.
    pub fn new(input: &'a str) -> Result<Self, ParseError> {
        ValueStr::new(input).map(Value::Str)
    }

    /// Borrow the inner value as a `str`, if it is one.
    ///
    /// Returns `None` if the inner value is a [`Value::Decimal`].
    pub fn as_str(&self) -> Option<&'a str> {
        match self {
            Self::Decimal(_) => None,
            Self::Str(s) => Some(s.as_str()),
        }
    }

    /// Parse a [`Decimal`] from this [`Value`].
    ///
    /// If this value is a [`Value::Decimal`], the decimal value is returned,
    /// otherwise if it's a [`Value::Str`] the value is parsed using the
    /// [`ValueStr::decimal`] method.
    pub fn decimal(&self) -> Result<Decimal, ParseError> {
        match self {
            Self::Decimal(x) => Ok(*x),
            Self::Str(s) => s.decimal(),
        }
    }

    /// Does this value parse successfully as a decimal?
    pub fn is_decimal(&self) -> bool {
        self.decimal().is_ok()
    }
}

impl<'a> From<Decimal> for Value<'a> {
    fn from(decimal: Decimal) -> Value<'a> {
        Value::Decimal(decimal)
    }
}

impl<'a> TryFrom<u32> for Value<'a> {
    type Error = ParseError;

    fn try_from(decimal: u32) -> Result<Value<'a>, ParseError> {
        i32::try_from(decimal)
            .ok()
            .map(Into::into)
            .ok_or(ParseError::TooLong)
    }
}

impl<'a> TryFrom<&'a str> for Value<'a> {
    type Error = ParseError;

    fn try_from(input: &'a str) -> Result<Self, ParseError> {
        Self::new(input)
    }
}

impl<'a> fmt::Display for Value<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decimal(x) => write!(f, "{}", x),
            Self::Str(s) => f.write_str(s.as_str()),
        }
    }
}

impl<'a> fmt::Debug for Value<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decimal(x) => f.debug_tuple("Value::Decimal").field(x).finish(),
            Self::Str(s) => f.debug_tuple("Value::Str").field(s).finish(),
        }
    }
}

/// Algorithm parameter value string.
///
/// Parameter values are defined in the [PHC string format specification][1].
///
/// # Constraints
/// - ASCII-encoded string consisting of the characters `[a-zA-Z0-9/+.-]`
///   (lowercase letters, digits, and the minus sign)
/// - Minimum length: 0 (i.e. empty values are allowed)
/// - Maximum length: 48 ASCII characters (i.e. 48-bytes)
///
/// # Additional Notes
/// The PHC spec allows for algorithm-defined maximum lengths for parameter
/// values, however in the interest of interoperability this library defines a
/// [`ValueStr::max_len`] of 48 ASCII characters.
///
/// [1]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
/// [2]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#argon2-encoding
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct ValueStr<'a>(&'a str);

impl<'a> ValueStr<'a> {
    /// Maximum length of an [`ValueStr`] - 48 ASCII characters (i.e. 48-bytes).
    ///
    /// This value is selected based on the maximum value size used in the
    /// [Argon2 Encoding][1] as described in the PHC string format specification.
    /// Namely the `data` parameter, when encoded as B64, can be up to 43
    /// characters.
    ///
    /// This implementation rounds that up to 48 as a safe maximum limit.
    ///
    /// [1]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#argon2-encoding
    pub const fn max_len() -> usize {
        MAX_LENGTH
    }

    /// Parse a [`ValueStr`] from the provided `str`, validating it according to
    /// the PHC string format's rules.
    pub fn new(input: &'a str) -> Result<Self, ParseError> {
        if input.as_bytes().len() > MAX_LENGTH {
            return Err(ParseError::TooLong);
        }

        // Check that the characters are permitted in a PHC parameter value.
        assert_valid_value(input)?;
        Ok(Self(input))
    }

    /// Attempt to decode a [`b64`]-encoded [`ValueStr`], writing the decoded
    /// result into the provided buffer, and returning a slice of the buffer
    /// containing the decoded result on success.
    ///
    /// Examples of "B64"-encoded parameters in practice are the `keyid` and
    /// `data` parameters used by the [Argon2 Encoding][1] as described in the
    /// PHC string format specification.
    ///
    /// [1]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#argon2-encoding
    pub fn b64_decode<'b>(&self, buf: &'b mut [u8]) -> Result<&'b [u8], B64Error> {
        b64::decode(self.as_str(), buf)
    }

    /// Borrow this value as a `str`.
    pub fn as_str(&self) -> &'a str {
        self.0
    }

    /// Borrow this value as bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.as_str().as_bytes()
    }

    /// Get the length of this value in ASCII characters.
    pub fn len(&self) -> usize {
        self.as_str().len()
    }

    /// Is this value empty?
    pub fn is_empty(&self) -> bool {
        self.as_str().is_empty()
    }

    /// Attempt to parse this [`ValueStr`] as a PHC-encoded decimal (i.e. integer).
    ///
    /// Decimal values are integers which follow the rules given in the
    /// ["Decimal Encoding" section of the PHC string format specification][1].
    ///
    /// The decimal encoding rules are as follows:
    /// > For an integer value x, its decimal encoding consist in the following:
    /// >
    /// > - If x < 0, then its decimal encoding is the minus sign - followed by the decimal
    ///     encoding of -x.
    /// > - If x = 0, then its decimal encoding is the single character 0.
    /// > - If x > 0, then its decimal encoding is the smallest sequence of ASCII digits that
    /// >   matches its value (i.e. there is no leading zero).
    /// >
    /// > Thus, a value is a valid decimal for an integer x if and only if all of the following hold true:
    /// >
    /// > - The first character is either a - sign, or an ASCII digit.
    /// > - All characters other than the first are ASCII digits.
    /// > - If the first character is - sign, then there is at least another character, and the
    ///     second character is not a 0.
    /// > - If the string consists in more than one character, then the first one cannot be a 0.
    ///
    /// [1]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#decimal-encoding
    // TODO(tarcieri): support for negative decimal values (is there a use case?)
    pub fn decimal(&self) -> Result<Decimal, ParseError> {
        let value = self.as_str();

        // Empty strings aren't decimals
        if value.is_empty() {
            return Err(ParseError::Empty);
        }

        // Ensure all characters are digits
        for c in value.chars() {
            if !matches!(c, '0'..='9') {
                return Err(ParseError::InvalidChar(c));
            }
        }

        // Disallow leading zeroes
        if value.starts_with('0') && value.len() > 1 {
            return Err(ParseError::InvalidChar('0'));
        }

        value.parse().map_err(|_| {
            // In theory a value overflow should be the only potential error here.
            // When `ParseIntError::kind` is stable it might be good to double check:
            // <https://github.com/rust-lang/rust/issues/22639>
            ParseError::TooLong
        })
    }

    /// Does this value parse successfully as a decimal?
    pub fn is_decimal(&self) -> bool {
        self.decimal().is_ok()
    }
}

impl<'a> AsRef<str> for ValueStr<'a> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<'a> TryFrom<&'a str> for ValueStr<'a> {
    type Error = ParseError;

    fn try_from(input: &'a str) -> Result<Self, ParseError> {
        Self::new(input)
    }
}

impl<'a> TryFrom<ValueStr<'a>> for Decimal {
    type Error = ParseError;

    fn try_from(value: ValueStr<'a>) -> Result<Decimal, ParseError> {
        Decimal::try_from(&value)
    }
}

impl<'a> TryFrom<&ValueStr<'a>> for Decimal {
    type Error = ParseError;

    fn try_from(value: &ValueStr<'a>) -> Result<Decimal, ParseError> {
        value.decimal()
    }
}

impl<'a> fmt::Display for ValueStr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Are all of the given bytes allowed in a [`Value`]?
fn assert_valid_value(input: &str) -> Result<(), ParseError> {
    for c in input.chars() {
        if !is_char_valid(c) {
            return Err(ParseError::InvalidChar(c));
        }
    }

    Ok(())
}

/// Ensure the given ASCII character (i.e. byte) is allowed in a [`Value`].
fn is_char_valid(c: char) -> bool {
    matches!(c, 'A' ..= 'Z' | 'a'..='z' | '0'..='9' | '/' | '+' | '.' | '-')
}

#[cfg(test)]
mod tests {
    use super::{ParseError, ValueStr};
    use core::convert::TryFrom;

    // Invalid value examples
    const INVALID_CHAR: &str = "x;y";
    const INVALID_TOO_LONG: &str = "0123456789112345678921234567893123456789412345678";
    const INVALID_CHAR_AND_TOO_LONG: &str = "0!23456789112345678921234567893123456789412345678";

    //
    // Decimal parsing tests
    //

    #[test]
    fn decimal_value() {
        let valid_decimals = &[("0", 0i32), ("1", 1i32), ("2147483647", i32::MAX)];

        for &(s, i) in valid_decimals {
            let value = ValueStr::new(s).unwrap();
            assert!(value.is_decimal());
            assert_eq!(value.decimal().unwrap(), i)
        }
    }

    #[test]
    fn reject_decimal_with_leading_zero() {
        let value = ValueStr::new("01").unwrap();
        let err = i32::try_from(value).err().unwrap();
        assert!(matches!(err, ParseError::InvalidChar('0')));
    }

    #[test]
    fn reject_overlong_decimal() {
        let value = ValueStr::new("2147483648").unwrap();
        let err = i32::try_from(value).err().unwrap();
        assert_eq!(err, ParseError::TooLong);
    }

    #[test]
    fn reject_negative() {
        let value = ValueStr::new("-1").unwrap();
        let err = i32::try_from(value).err().unwrap();
        assert!(matches!(err, ParseError::InvalidChar('-')));
    }

    //
    // String parsing tests
    //

    #[test]
    fn string_value() {
        let valid_examples = [
            "",
            "X",
            "x",
            "xXx",
            "a+b.c-d",
            "1/2",
            "01234567891123456789212345678931",
        ];

        for &example in &valid_examples {
            let value = ValueStr::new(example).unwrap();
            assert_eq!(value.as_str(), example);
        }
    }

    #[test]
    fn reject_invalid_char() {
        let err = ValueStr::new(INVALID_CHAR).err().unwrap();
        assert!(matches!(err, ParseError::InvalidChar(';')));
    }

    #[test]
    fn reject_too_long() {
        let err = ValueStr::new(INVALID_TOO_LONG).err().unwrap();
        assert_eq!(err, ParseError::TooLong);
    }

    #[test]
    fn reject_invalid_char_and_too_long() {
        let err = ValueStr::new(INVALID_CHAR_AND_TOO_LONG).err().unwrap();
        assert_eq!(err, ParseError::TooLong);
    }
}
