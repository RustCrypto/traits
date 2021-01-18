use super::{FixedOutput, Reset, Update};
use generic_array::typenum::Unsigned;
use generic_array::{ArrayLength, GenericArray};

/// The `Digest` trait specifies an interface common for digest functions.
///
/// It's a convenience wrapper around [`Update`], [`FixedOutput`], [`Reset`],
/// [`Clone`], and [`Default`] traits. It also provides additional convenience methods.
pub trait Digest {
    /// Output size for `Digest`
    type OutputSize: ArrayLength<u8>;

    /// Create new hasher instance
    fn new() -> Self;

    /// Digest data, updating the internal state.
    ///
    /// This method can be called repeatedly for use with streaming messages.
    fn update(&mut self, data: impl AsRef<[u8]>);

    /// Digest input data in a chained manner.
    fn chain(self, data: impl AsRef<[u8]>) -> Self
    where
        Self: Sized;

    /// Retrieve result and consume hasher instance.
    fn finalize(self) -> Output<Self>;

    /// Retrieve result and reset hasher instance.
    ///
    /// This method sometimes can be more efficient compared to hasher
    /// re-creation.
    fn finalize_reset(&mut self) -> Output<Self>;

    /// Write result into provided array and consume the hasher instance.
    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>);

    /// Write result into provided array and reset the hasher instance.
    fn finalize_into_reset(&mut self, out: &mut GenericArray<u8, Self::OutputSize>);

    /// Reset hasher instance to its initial state.
    fn reset(&mut self);

    /// Get output size of the hasher
    fn output_size() -> usize;

    /// Convenience function to compute hash of the `data`. It will handle
    /// hasher creation, data feeding and finalization.
    ///
    /// Example:
    ///
    /// ```rust,ignore
    /// println!("{:x}", sha2::Sha256::digest(b"Hello world"));
    /// ```
    fn digest(data: &[u8]) -> Output<Self>;
}

impl<D: Update + FixedOutput + Reset + Clone + Default> Digest for D {
    type OutputSize = <Self as FixedOutput>::OutputSize;

    #[inline]
    fn new() -> Self {
        Self::default()
    }

    #[inline]
    fn update(&mut self, data: impl AsRef<[u8]>) {
        Update::update(self, data.as_ref());
    }

    #[inline]
    fn chain(mut self, data: impl AsRef<[u8]>) -> Self
    where
        Self: Sized,
    {
        Update::update(&mut self, data.as_ref());
        self
    }

    #[inline]
    fn finalize(self) -> Output<Self> {
        self.finalize_fixed()
    }

    #[inline]
    fn finalize_reset(&mut self) -> Output<Self> {
        self.finalize_fixed_reset()
    }

    #[inline]
    fn finalize_into(self, out: &mut Output<Self>) {
        self.finalize_into(out);
    }

    #[inline]
    fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
        self.finalize_into_reset(out);
    }

    #[inline]
    fn reset(&mut self) {
        Reset::reset(self)
    }

    #[inline]
    fn output_size() -> usize {
        Self::OutputSize::to_usize()
    }

    #[inline]
    fn digest(data: &[u8]) -> Output<Self> {
        let mut hasher = Self::default();
        Update::update(&mut hasher, data);
        hasher.finalize_fixed()
    }
}

/// Fixed of fixed-sized hash-function used by [`Digest`] methods.
pub type Output<D> = GenericArray<u8, <D as Digest>::OutputSize>;
