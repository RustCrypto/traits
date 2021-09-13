use super::{OutputSizeUser, Output};
use subtle::{Choice, ConstantTimeEq};

/// Fixed size output value which provides a safe [`Eq`] implementation that
/// runs in constant time.
///
/// It is useful for implementing Message Authentication Codes (MACs).
#[derive(Clone)]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
pub struct CtOutput<T: OutputSizeUser> {
    bytes: Output<T>,
}

impl<T: OutputSizeUser> CtOutput<T> {
    /// Create a new [`CtOutput`] value.
    pub fn new(bytes: Output<T>) -> Self {
        Self { bytes }
    }

    /// Get the inner [`Output`] array this type wraps.
    pub fn into_bytes(self) -> Output<T> {
        self.bytes
    }
}

impl<T: OutputSizeUser> From<Output<T>> for CtOutput<T> {
    fn from(bytes: Output<T>) -> Self {
        Self { bytes }
    }
}

impl<'a, T: OutputSizeUser> From<&'a Output<T>> for CtOutput<T> {
    fn from(bytes: &'a Output<T>) -> Self {
        bytes.clone().into()
    }
}

impl<T: OutputSizeUser> ConstantTimeEq for CtOutput<T> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl<T: OutputSizeUser> PartialEq for CtOutput<T> {
    fn eq(&self, x: &CtOutput<T>) -> bool {
        self.ct_eq(x).unwrap_u8() == 1
    }
}

impl<T: OutputSizeUser> Eq for CtOutput<T> {}
