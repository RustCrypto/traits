use super::{FixedOutput, Output};
use subtle::{Choice, ConstantTimeEq};

/// Fixed size output value which provides a safe [`Eq`] implementation that
/// runs in constant time.
///
/// It is useful for implementing Message Authentication Codes (MACs).
#[derive(Clone)]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
pub struct CtOutput<T: FixedOutput> {
    bytes: Output<T>,
}

impl<T: FixedOutput> CtOutput<T> {
    /// Create a new [`CtOutput`] value.
    pub fn new(bytes: Output<T>) -> Self {
        Self { bytes }
    }

    /// Get the inner [`Output`] array this type wraps.
    pub fn into_bytes(self) -> Output<T> {
        self.bytes
    }
}

impl<T: FixedOutput> From<Output<T>> for CtOutput<T> {
    fn from(bytes: Output<T>) -> Self {
        Self { bytes }
    }
}

impl<'a, T: FixedOutput> From<&'a Output<T>> for CtOutput<T> {
    fn from(bytes: &'a Output<T>) -> Self {
        bytes.clone().into()
    }
}

impl<T: FixedOutput> ConstantTimeEq for CtOutput<T> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl<T: FixedOutput> PartialEq for CtOutput<T> {
    fn eq(&self, x: &CtOutput<T>) -> bool {
        self.ct_eq(x).unwrap_u8() == 1
    }
}

impl<T: FixedOutput> Eq for CtOutput<T> {}
