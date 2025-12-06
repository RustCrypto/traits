use crate::{Error, Result};
use core::{
    fmt,
    ops::Deref,
    str::{self, FromStr},
};

/// Buffer for storing short stack-allocated strings.
#[derive(Clone, Copy, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub(super) struct StringBuf<const N: usize> {
    /// Length of the string in ASCII characters (i.e. bytes).
    pub(super) length: u8,

    /// Byte array containing an ASCII-encoded string.
    pub(super) bytes: [u8; N],
}

impl<const N: usize> StringBuf<N> {
    /// Create a new string buffer containing the given string
    pub(super) const fn new(s: &str) -> Result<Self> {
        if s.len() > N || s.len() > u8::MAX as usize {
            return Err(Error::TooLong);
        }

        let mut bytes = [0u8; N];
        let mut i = 0;

        while i < s.len() {
            bytes[i] = s.as_bytes()[i];
            i += 1;
        }

        Ok(Self {
            bytes,
            length: s.len() as u8,
        })
    }
}

impl<const N: usize> AsRef<str> for StringBuf<N> {
    fn as_ref(&self) -> &str {
        str::from_utf8(&self.bytes[..(self.length as usize)]).expect("should be valid UTF-8")
    }
}

impl<const N: usize> Default for StringBuf<N> {
    fn default() -> Self {
        StringBuf {
            bytes: [0u8; N],
            length: 0,
        }
    }
}

impl<const N: usize> Deref for StringBuf<N> {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_ref()
    }
}

impl<const N: usize> FromStr for StringBuf<N> {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

impl<const N: usize> TryFrom<&str> for StringBuf<N> {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

impl<const N: usize> fmt::Debug for StringBuf<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl<const N: usize> fmt::Display for StringBuf<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl<const N: usize> fmt::Write for StringBuf<N> {
    fn write_str(&mut self, input: &str) -> fmt::Result {
        const { debug_assert!(N <= u8::MAX as usize) }

        let bytes = input.as_bytes();
        let length = self.length as usize;
        let new_length = length.checked_add(bytes.len()).ok_or(fmt::Error)?;

        if new_length > N {
            return Err(fmt::Error);
        }

        self.bytes[length..new_length].copy_from_slice(bytes);
        self.length = new_length.try_into().map_err(|_| fmt::Error)?;

        Ok(())
    }
}
