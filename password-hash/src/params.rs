//! Algorithm parameters.

use crate::{
    errors::{ParamsError, ParseError},
    value::Value,
    Ident,
};
use core::{
    convert::{TryFrom, TryInto},
    fmt,
    iter::FromIterator,
    ops::Index,
    slice,
};

/// Individual parameter name/value pair.
pub type Pair<'a> = (Ident<'a>, Value<'a>);

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
pub struct Params<'a> {
    /// Name/value pairs.
    ///
    /// Name (i.e. the [`Ident`]) *MUST* be unique.
    pairs: [Option<Pair<'a>>; MAX_LENGTH],
}

impl<'a> Params<'a> {
    /// Create new empty [`Params`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Instantiate [`Params`] from a slice of name/value pairs.
    pub fn from_slice(pairs: &[Pair<'a>]) -> Result<Self, ParamsError> {
        let mut result = Self::default();

        for (name, value) in pairs.iter().cloned() {
            result = result.add(name, value)?;
        }

        Ok(result)
    }

    /// Add another pair to the [`Params`].
    pub fn add(mut self, name: Ident<'a>, value: Value<'a>) -> Result<Self, ParamsError> {
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
    pub fn get(&self, name: Ident<'a>) -> Option<&Value<'a>> {
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

    /// Iterate over the parameters.
    pub fn iter(&self) -> Iter<'a, '_> {
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

impl<'a> FromIterator<Pair<'a>> for Params<'a> {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = Pair<'a>>,
    {
        iter.into_iter()
            .fold(Params::new(), |params, (name, value)| {
                params.add(name, value).expect("error adding param")
            })
    }
}

// Note: this uses `TryFrom` instead of `FromStr` to support a lifetime on
// the `str` the value is being parsed from.
impl<'a> TryFrom<&'a str> for Params<'a> {
    type Error = ParamsError;

    fn try_from(input: &'a str) -> Result<Self, ParamsError> {
        let mut params = Params::new();

        if input.is_empty() {
            return Ok(params);
        }

        for mut param in input
            .split(PARAMS_DELIMITER)
            .map(|p| p.split(PAIR_DELIMITER))
        {
            let name = param
                .next()
                .ok_or(ParseError::InvalidChar(PAIR_DELIMITER))?;

            let value = param
                .next()
                .ok_or(ParseError::InvalidChar(PAIR_DELIMITER))?;

            if param.next().is_some() {
                return Err(ParseError::TooLong.into());
            }

            params = params.add(name.try_into()?, value.try_into()?)?;
        }

        Ok(params)
    }
}

impl<'a> Index<Ident<'a>> for Params<'a> {
    type Output = Value<'a>;

    fn index(&self, name: Ident<'a>) -> &Value<'a> {
        self.get(name)
            .unwrap_or_else(|| panic!("no parameter with name `{}`", name))
    }
}

impl<'a> Index<&'a str> for Params<'a> {
    type Output = Value<'a>;

    fn index(&self, name: &'a str) -> &Value<'a> {
        &self[Ident::try_from(name).expect("invalid parameter name")]
    }
}

impl<'a> fmt::Display for Params<'a> {
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

impl<'a> fmt::Debug for Params<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(
                self.iter()
                    .map(|&(ref name, ref value)| (name.as_str(), value)),
            )
            .finish()
    }
}

/// Iterator over algorithm parameters stored in a [`Params`] struct.
pub struct Iter<'a, 'b> {
    /// Inner slice iterator this newtype wrapper is built upon.
    inner: slice::Iter<'b, Option<Pair<'a>>>,
}

impl<'a, 'b> Iterator for Iter<'a, 'b> {
    type Item = &'b Pair<'a>;

    fn next(&mut self) -> Option<&'b Pair<'a>> {
        self.inner.next()?.as_ref()
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::string::ToString;
    use core::convert::TryFrom;

    use super::{FromIterator, Ident, Params, ParamsError};

    #[test]
    fn add_chain() {
        let params = Params::new()
            .add(Ident::new("a"), 1i32.into())
            .and_then(|p| p.add(Ident::new("b"), 2i32.into()))
            .and_then(|p| p.add(Ident::new("c"), 3i32.into()))
            .unwrap();

        assert_eq!(params.len(), 3);
        assert_eq!(params["a"].decimal().unwrap(), 1);
        assert_eq!(params["b"].decimal().unwrap(), 2);
        assert_eq!(params["c"].decimal().unwrap(), 3);
    }

    #[test]
    fn duplicate_names() {
        let name = Ident::new("a");
        let params = Params::new().add(name, 1i32.into()).unwrap();
        let err = params.add(name, 2i32.into()).err().unwrap();
        assert_eq!(err, ParamsError::DuplicateName);
    }

    #[test]
    fn from_slice() {
        let params = Params::from_slice(&[
            (Ident::new("a"), 1i32.into()),
            (Ident::new("b"), 2i32.into()),
            (Ident::new("c"), 3i32.into()),
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
                (Ident::new("a"), 1i32.into()),
                (Ident::new("b"), 2i32.into()),
                (Ident::new("c"), 3i32.into()),
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
            (Ident::new("a"), 1i32.into()),
            (Ident::new("b"), 2i32.into()),
            (Ident::new("c"), 3i32.into()),
        ])
        .unwrap();

        let mut i = params.iter();
        assert_eq!(i.next(), Some(&(Ident::new("a"), 1i32.into())));
        assert_eq!(i.next(), Some(&(Ident::new("b"), 2i32.into())));
        assert_eq!(i.next(), Some(&(Ident::new("c"), 3i32.into())));
        assert_eq!(i.next(), None);
    }

    //
    // `FromStr` tests
    //

    #[test]
    fn parse_empty() {
        let params = Params::try_from("").unwrap();
        assert!(params.is_empty());
    }

    #[test]
    fn parse_one() {
        let params = Params::try_from("a=1").unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params["a"].decimal().unwrap(), 1);
    }

    #[test]
    fn parse_many() {
        let params = Params::try_from("a=1,b=2,c=3").unwrap();
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
        let params = Params::from_slice(&[(Ident::new("a"), 1i32.into())]).unwrap();
        assert_eq!(params.to_string(), "a=1");
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn display_many() {
        let params = Params::from_slice(&[
            (Ident::new("a"), 1i32.into()),
            (Ident::new("b"), 2i32.into()),
            (Ident::new("c"), 3i32.into()),
        ])
        .unwrap();

        assert_eq!(params.to_string(), "a=1,b=2,c=3");
    }
}
