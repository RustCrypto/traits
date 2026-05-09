use core::ops::{Deref, DerefMut};

/// `Box`-like type providing opportunistic heap allocation when the `alloc` feature is available
/// that falls back to stack allocation when it's unavailable.
#[derive(Clone, Debug, PartialEq)]
pub struct MaybeBox<T> {
    #[cfg(not(feature = "alloc"))]
    inner: T,
    #[cfg(feature = "alloc")]
    inner: alloc::boxed::Box<T>,
}

impl<T> MaybeBox<T> {
    /// Create a new `MaybeBox`, using `Box` if `alloc` is available.
    #[inline]
    pub fn new(inner: T) -> Self {
        #[cfg(not(feature = "alloc"))]
        {
            Self { inner }
        }
        #[cfg(feature = "alloc")]
        Self {
            inner: alloc::boxed::Box::new(inner),
        }
    }

    /// Move the contents out of a [`MaybeBox`].
    ///
    /// This emulates the compiler magic that allows moving out of a box with `*my_box`.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> T {
        #[cfg(not(feature = "alloc"))]
        {
            self.inner
        }
        #[cfg(feature = "alloc")]
        {
            *self.inner
        }
    }
}

impl<T> Deref for MaybeBox<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for MaybeBox<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
