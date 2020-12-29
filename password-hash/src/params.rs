//! Algorithm parameters.

mod value;

pub use self::value::{Decimal, Value};

use crate::{
    errors::{ParamsError, ParseError},
    Ident,
};
use core::{fmt, iter::FromIterator, ops::Index, slice, str::FromStr};

/// Individual parameter name/value pair.
pub type Pair = (Ident, Value);

/// Delimiter character between name/value pairs.
pub(crate) const PAIR_DELIMITER: char = '=';

/// Delimiter character between parameters.
pub(crate) const PARAMS_DELIMITER: char = ',';

/// Maximum number of supported parameters.
const MAX_LENGTH: usize = 8;

/// Algorithm parameters.
///
/// The [PHC string format specification][1] defines a set of optional
/// algorithm-specific name/value pairs which can be encoded into a
/// PHC-formatted parameter string as follows:
///
/// ```text
/// $<param>=<value>(,<param>=<value>)*
/// ```
///
/// This type represents that set of parameters.
///
/// [1]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#specification
#[derive(Clone, Default, Eq, PartialEq)]
pub struct Params {
    /// Name/value pairs.
    ///
    /// Name (i.e. the [`Ident`]) *MUST* be unique.
    pairs: [Option<Pair>; MAX_LENGTH],
}

impl Params {
    /// Create new empty [`Params`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Instantiate [`Params`] from a slice of name/value pairs.
    pub fn from_slice(pairs: &[Pair]) -> Result<Self, ParamsError> {
        let mut result = Self::default();

        for (name, value) in pairs.iter().cloned() {
            result = result.add(name, value)?;
        }

        Ok(result)
    }

    /// Add another pair to the [`Params`].
    pub fn add(mut self, name: Ident, value: Value) -> Result<Self, ParamsError> {
        for entry in &mut self.pairs {
            match entry {
                Some((n, _)) => {
                    // If slot is occupied, ensure the name isn't a duplicate
                    if *n == name {
                        // TODO(tarcieri): make idempotent? (i.e. ignore dupes if the value is the same)
                        return Err(ParamsError::DuplicateName);
                    }
                }
                None => {
                    // Use free slot if available
                    *entry = Some((name, value));
                    return Ok(self);
                }
            }
        }

        Err(ParamsError::MaxExceeded)
    }

    /// Get a parameter value by name.
    pub fn get(&self, name: Ident) -> Option<&Value> {
        for entry in &self.pairs {
            match entry {
                Some((n, v)) => {
                    if *n == name {
                        return Some(v);
                    }
                }
                None => return None,
            }
        }

        None
    }

    /// Iterate over the parameters using [`Iter`].
    pub fn iter(&self) -> Iter<'_> {
        Iter {
            inner: self.pairs.iter(),
        }
    }

    /// Get the count of the number of parameters.
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    /// Is this set of parameters empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl FromIterator<Pair> for Params {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = Pair>,
    {
        iter.into_iter()
            .fold(Params::new(), |params, (name, value)| {
                params.add(name, value).expect("error adding param")
            })
    }
}

impl FromStr for Params {
    type Err = ParamsError;

    fn from_str(input: &str) -> Result<Self, ParamsError> {
        let mut params = Params::new();

        if input.is_empty() {
            return Ok(params);
        }

        for mut param in input
            .split(PARAMS_DELIMITER)
            .map(|p| p.split(PAIR_DELIMITER))
        {
            let name = param.next().ok_or(ParseError {
                invalid_char: Some(PAIR_DELIMITER),
                too_long: false,
            })?;

            let value = param.next().ok_or(ParseError {
                invalid_char: Some(PAIR_DELIMITER),
                too_long: false,
            })?;

            if param.next().is_some() {
                return Err(ParseError::too_long().into());
            }

            params = params.add(name.parse()?, value.parse()?)?;
        }

        Ok(params)
    }
}

impl Index<Ident> for Params {
    type Output = Value;

    fn index(&self, name: Ident) -> &Value {
        self.get(name)
            .unwrap_or_else(|| panic!("no parameter with name `{}`", name))
    }
}

impl Index<&str> for Params {
    type Output = Value;

    fn index(&self, name: &str) -> &Value {
        let name = name.parse::<Ident>().expect("invalid parameter name");
        &self[name]
    }
}

impl fmt::Display for Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.len();

        for (i, (name, value)) in self.iter().enumerate() {
            write!(f, "{}{}{}", name, PAIR_DELIMITER, value)?;

            if i + 1 != n {
                write!(f, "{}", PARAMS_DELIMITER)?;
            }
        }

        Ok(())
    }
}

impl fmt::Debug for Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(
                self.iter()
                    .map(|&(ref name, ref value)| (name.as_ref(), value.as_ref())),
            )
            .finish()
    }
}

/// Iterator over algorithm parameters stored in a [`Params`] struct.
pub struct Iter<'a> {
    /// Inner slice iterator this newtype wrapper is built upon.
    inner: slice::Iter<'a, Option<Pair>>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a Pair;

    fn next(&mut self) -> Option<&'a Pair> {
        self.inner.next()?.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::{FromIterator, Ident, Params, ParamsError};

    #[cfg(feature = "alloc")]
    use alloc::string::ToString;

    #[test]
    fn add_chain() {
        let params = Params::new()
            .add("a".parse().unwrap(), 1i32.into())
            .and_then(|p| p.add("b".parse().unwrap(), 2i32.into()))
            .and_then(|p| p.add("c".parse().unwrap(), 3i32.into()))
            .unwrap();

        assert_eq!(params.len(), 3);
        assert_eq!(params["a"].decimal().unwrap(), 1);
        assert_eq!(params["b"].decimal().unwrap(), 2);
        assert_eq!(params["c"].decimal().unwrap(), 3);
    }

    #[test]
    fn duplicate_names() {
        let name = "a".parse::<Ident>().unwrap();
        let params = Params::new().add(name, 1i32.into()).unwrap();
        let err = params.add(name, 2i32.into()).err().unwrap();
        assert_eq!(err, ParamsError::DuplicateName);
    }

    #[test]
    fn from_slice() {
        let params = Params::from_slice(&[
            ("a".parse().unwrap(), 1i32.into()),
            ("b".parse().unwrap(), 2i32.into()),
            ("c".parse().unwrap(), 3i32.into()),
        ])
        .unwrap();

        assert_eq!(params.len(), 3);
        assert_eq!(params["a"].decimal().unwrap(), 1);
        assert_eq!(params["b"].decimal().unwrap(), 2);
        assert_eq!(params["c"].decimal().unwrap(), 3);
    }

    #[test]
    fn from_iterator() {
        let params = Params::from_iter(
            [
                ("a".parse().unwrap(), 1i32.into()),
                ("b".parse().unwrap(), 2i32.into()),
                ("c".parse().unwrap(), 3i32.into()),
            ]
            .iter()
            .cloned(),
        );

        assert_eq!(params.len(), 3);
        assert_eq!(params["a"].decimal().unwrap(), 1);
        assert_eq!(params["b"].decimal().unwrap(), 2);
        assert_eq!(params["c"].decimal().unwrap(), 3);
    }

    #[test]
    fn iter() {
        let params = Params::from_slice(&[
            ("a".parse().unwrap(), 1i32.into()),
            ("b".parse().unwrap(), 2i32.into()),
            ("c".parse().unwrap(), 3i32.into()),
        ])
        .unwrap();

        let mut i = params.iter();
        assert_eq!(i.next(), Some(&("a".parse().unwrap(), 1i32.into())));
        assert_eq!(i.next(), Some(&("b".parse().unwrap(), 2i32.into())));
        assert_eq!(i.next(), Some(&("c".parse().unwrap(), 3i32.into())));
        assert_eq!(i.next(), None);
    }

    //
    // `FromStr` tests
    //

    #[test]
    fn parse_empty() {
        let params = "".parse::<Params>().unwrap();
        assert!(params.is_empty());
    }

    #[test]
    fn parse_one() {
        let params = "a=1".parse::<Params>().unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params["a"].decimal().unwrap(), 1);
    }

    #[test]
    fn parse_many() {
        let params = "a=1,b=2,c=3".parse::<Params>().unwrap();
        assert_eq!(params.len(), 3);
        assert_eq!(params["a"].decimal().unwrap(), 1);
        assert_eq!(params["b"].decimal().unwrap(), 2);
        assert_eq!(params["c"].decimal().unwrap(), 3);
    }

    //
    // `Display` tests
    //

    #[test]
    #[cfg(feature = "alloc")]
    fn display_empty() {
        let params = Params::new();
        assert_eq!(params.to_string(), "");
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn display_one() {
        let params = Params::from_slice(&[("a".parse().unwrap(), 1i32.into())]).unwrap();
        assert_eq!(params.to_string(), "a=1");
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn display_many() {
        let params = Params::from_slice(&[
            ("a".parse().unwrap(), 1i32.into()),
            ("b".parse().unwrap(), 2i32.into()),
            ("c".parse().unwrap(), 3i32.into()),
        ])
        .unwrap();

        assert_eq!(params.to_string(), "a=1,b=2,c=3");
    }
}
