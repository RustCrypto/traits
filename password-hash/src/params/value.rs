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
use core::{
    convert::TryFrom,
    fmt::{self, Write},
    str::{self, FromStr},
};

/// Maximum size of a parameter value in ASCII characters.
///
/// This value is selected based on the maximum value size used in the
/// [Argon2 Encoding][1] as described in the PHC string format specification.
///
/// Namely the `data` parameter, when encoded as B64, can be up to 43
/// characters.
///
/// This implementation rounds that up to 48 as a safe maximum limit.
///
/// [1]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#argon2-encoding
const MAX_LENGTH: usize = 48;

/// Type used to represent decimal (i.e. integer) values.
pub type Decimal = i32;

/// Algorithm parameter value.
///
/// Parameter values are defined in the [PHC string format specification][1].
///
/// # Constraints
/// - ASCII-encoded string consisting of the characters `[a-zA-Z0-9/+.-]`
///   (lowercase letters, digits, and the minus sign)
/// - Minimum length: 0 (i.e. empty values are allowed)
/// - Maximum length: 32 ASCII characters (i.e. 32-bytes)
///
/// # Additional Notes
/// The PHC spec allows for algorithm-defined maximum lengths for parameter
/// values, however in the interest of interoperability this library defines a
/// [`Value::max_len`] of 48 ASCII characters.
///
/// See method documentation for more information.
///
/// [1]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
/// [2]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#argon2-encoding
#[derive(Copy, Clone, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Value {
    /// Byte array containing an ASCII-encoded string.
    bytes: [u8; MAX_LENGTH],

    /// Length of the string in ASCII characters (i.e. bytes).
    length: u8,
}

impl Value {
    /// Maximum length of an [`Value`] - 48 ASCII characters (i.e. 48-bytes).
    ///
    /// This value is selected based on the maximum value size used in the
    /// [Argon2 Encoding][1] as described in the PHC string format specification.
    ///
    /// Namely the `data` parameter, when encoded as B64, can be up to 43
    /// characters.
    ///
    /// This implementation rounds that up to 48 as a safe maximum limit.
    ///
    /// [1]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#argon2-encoding
    pub const fn max_len() -> usize {
        MAX_LENGTH
    }

    /// Create a new, empty [`Value`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Encode the given byte slice as [`b64`] and store it in a [`Value`].
    ///
    /// Examples of "B64"-encoded parameters in practice are the `keyid` and
    /// `data` parameters used by the [Argon2 Encoding][1] as described in the
    /// PHC string format specification.
    ///
    /// [1]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#argon2-encoding
    pub fn b64_encode(input: &[u8]) -> Result<Self, B64Error> {
        let mut bytes = [0u8; MAX_LENGTH];
        let encoded_len = b64::encode(input, &mut bytes)?.len();
        Ok(Self {
            bytes,
            length: encoded_len as u8,
        })
    }

    /// Attempt to decode a [`b64`]-encoded [`Value`], writing the decoded
    /// result into the provided buffer, and returning a slice of the buffer
    /// containing the decoded result on success.
    ///
    /// Examples of "B64"-encoded parameters in practice are the `keyid` and
    /// `data` parameters used by the [Argon2 Encoding][1] as described in the
    /// PHC string format specification.
    ///
    /// [1]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#argon2-encoding
    pub fn b64_decode<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], B64Error> {
        b64::decode(self.as_str(), buf)
    }

    /// Borrow this value as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..(self.length as usize)]
    }

    /// Borrow this value as a `str`.
    pub fn as_str(&self) -> &str {
        str::from_utf8(self.as_bytes()).expect("malformed PHC param")
    }

    /// Get the length of this value in ASCII characters.
    pub fn len(&self) -> usize {
        self.as_str().len()
    }

    /// Is this value empty?
    pub fn is_empty(&self) -> bool {
        self.as_str().is_empty()
    }

    /// Attempt to parse this [`Value`] as a PHC-encoded decimal (i.e. integer).
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
            return Err(ParseError::default());
        }

        // Ensure all characters are digits
        for char in value.chars() {
            if !matches!(char, '0'..='9') {
                return Err(ParseError {
                    invalid_char: Some(char),
                    too_long: false,
                });
            }
        }

        // Disallow leading zeroes
        if value.starts_with('0') && value.len() > 1 {
            return Err(ParseError {
                invalid_char: Some('0'),
                too_long: false,
            });
        }

        value.parse().map_err(|_| {
            // In theory a value overflow should be the only potential error here.
            // When `ParseIntError::kind` is stable it might be good to double check:
            // <https://github.com/rust-lang/rust/issues/22639>
            ParseError::too_long()
        })
    }

    /// Does this value parse successfully as a decimal?
    pub fn is_decimal(&self) -> bool {
        self.decimal().is_ok()
    }
}

impl AsRef<str> for Value {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Default for Value {
    fn default() -> Self {
        Self {
            bytes: [0u8; MAX_LENGTH],
            length: 0,
        }
    }
}

impl FromStr for Value {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, ParseError> {
        // Check that the characters are permitted in a PHC parameter value.
        assert_valid_value(input).map_err(|mut e| {
            e.too_long = input.as_bytes().len() > MAX_LENGTH;
            e
        })?;

        let input = input.as_bytes();
        let mut bytes = [0u8; MAX_LENGTH];
        let output = bytes.get_mut(..input.len());

        if let Some(out) = output {
            out.copy_from_slice(input);
            let length = input.len() as u8;
            Ok(Self { bytes, length })
        } else {
            Err(ParseError::too_long())
        }
    }
}

impl From<Decimal> for Value {
    fn from(decimal: Decimal) -> Value {
        let mut value = Value::default();
        write!(&mut value, "{}", decimal).expect("decimal conversion error");
        value
    }
}

impl TryFrom<u32> for Value {
    type Error = ParseError;

    fn try_from(decimal: u32) -> Result<Value, ParseError> {
        i32::try_from(decimal)
            .ok()
            .map(Into::into)
            .ok_or_else(ParseError::too_long)
    }
}

impl TryFrom<Value> for Decimal {
    type Error = ParseError;

    fn try_from(value: Value) -> Result<Decimal, ParseError> {
        Decimal::try_from(&value)
    }
}

impl TryFrom<&Value> for Decimal {
    type Error = ParseError;

    fn try_from(value: &Value) -> Result<Decimal, ParseError> {
        value.decimal()
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Value").field(&self.as_str()).finish()
    }
}

impl Write for Value {
    fn write_str(&mut self, input: &str) -> fmt::Result {
        // Check that the characters are permitted in a PHC parameter value.
        assert_valid_value(input).map_err(|_| fmt::Error)?;

        let bytes = input.as_bytes();
        let length = self.length as usize;

        if length + bytes.len() > MAX_LENGTH {
            return Err(fmt::Error);
        }

        self.bytes[length..(length + bytes.len())].copy_from_slice(bytes);
        self.length += bytes.len() as u8;

        Ok(())
    }
}

/// Are all of the given bytes allowed in a [`Value`]?
fn assert_valid_value(input: &str) -> Result<(), ParseError> {
    for char in input.chars() {
        if !is_char_valid(char) {
            return Err(ParseError {
                invalid_char: Some(char),
                too_long: false,
            });
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
    use super::Value;
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
            let value = s.parse::<Value>().unwrap();
            assert!(value.is_decimal());
            assert_eq!(value.decimal().unwrap(), i)
        }
    }

    #[test]
    fn reject_decimal_with_leading_zero() {
        let value = "01".parse::<Value>().unwrap();
        let err = i32::try_from(value).err().unwrap();
        assert_eq!(err.invalid_char, Some('0'));
    }

    #[test]
    fn reject_overlong_decimal() {
        let value = "2147483648".parse::<Value>().unwrap();
        let err = i32::try_from(value).err().unwrap();
        assert!(err.too_long);
    }

    #[test]
    fn reject_negative() {
        let value = "-1".parse::<Value>().unwrap();
        let err = i32::try_from(value).err().unwrap();
        assert_eq!(err.invalid_char, Some('-'));
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
            let value = example.parse::<Value>().unwrap();
            assert_eq!(value.as_str(), example);
        }
    }

    #[test]
    fn reject_invalid_char() {
        let err = INVALID_CHAR.parse::<Value>().err().unwrap();
        assert_eq!(err.invalid_char, Some(';'));
        assert!(!err.too_long);
    }

    #[test]
    fn reject_too_long() {
        let err = INVALID_TOO_LONG.parse::<Value>().err().unwrap();
        assert_eq!(err.invalid_char, None);
        assert!(err.too_long);
    }

    #[test]
    fn reject_invalid_char_and_too_long() {
        let err = INVALID_CHAR_AND_TOO_LONG.parse::<Value>().err().unwrap();
        assert_eq!(err.invalid_char, Some('!'));
        assert!(err.too_long);
    }
}
