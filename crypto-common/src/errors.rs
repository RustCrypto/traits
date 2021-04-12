use core::fmt;

/// The error type returned when key and/or IV used in the [`FromKey`]
/// and [`FromKeyIv`] slice-based methods had an invalid length.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct InvalidLength;

impl fmt::Display for InvalidLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("Invalid Length")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidLength {}
