use super::{FixedOutput, FixedOutputReset, Reset, Update};
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

    /// Process data, updating the internal state.
    fn update(&mut self, data: impl AsRef<[u8]>);

    /// Process input data in a chained manner.
    fn chain_update(self, data: impl AsRef<[u8]>) -> Self;

    /// Retrieve result and consume hasher instance.
    fn finalize(self) -> Output<Self>;

    /// Write result into provided array and consume the hasher instance.
    fn finalize_into(self, out: &mut Output<Self>);

    /// Retrieve result and reset hasher instance.
    fn finalize_reset(&mut self) -> Output<Self>
    where
        Self: FixedOutputReset;

    /// Write result into provided array and reset the hasher instance.
    fn finalize_into_reset(&mut self, out: &mut Output<Self>)
    where
        Self: FixedOutputReset;

    /// Reset hasher instance to its initial state.
    fn reset(&mut self)
    where
        Self: Reset;

    /// Get output size of the hasher
    fn output_size() -> usize;

    /// Compute hash of `data`.
    fn digest(data: impl AsRef<[u8]>) -> Output<Self>;
}

impl<D: FixedOutput + Default + Update> Digest for D {
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
    fn chain_update(mut self, data: impl AsRef<[u8]>) -> Self {
        Update::update(&mut self, data.as_ref());
        self
    }

    #[inline]
    fn finalize(self) -> Output<Self> {
        FixedOutput::finalize_fixed(self)
    }

    #[inline]
    fn finalize_into(self, out: &mut Output<Self>) {
        FixedOutput::finalize_into(self, out);
    }

    #[inline]
    fn finalize_reset(&mut self) -> Output<Self>
    where
        Self: FixedOutputReset,
    {
        FixedOutputReset::finalize_fixed_reset(self)
    }

    #[inline]
    fn finalize_into_reset(&mut self, out: &mut Output<Self>)
    where
        Self: FixedOutputReset,
    {
        FixedOutputReset::finalize_into_reset(self, out);
    }

    #[inline]
    fn reset(&mut self)
    where
        Self: Reset,
    {
        Reset::reset(self)
    }

    #[inline]
    fn output_size() -> usize {
        Self::OutputSize::to_usize()
    }

    #[inline]
    fn digest(data: impl AsRef<[u8]>) -> Output<Self> {
        let mut hasher = Self::default();
        hasher.update(data.as_ref());
        hasher.finalize()
    }
}

/// Fixed of fixed-sized hash-function used by [`Digest`] methods.
pub type Output<D> = GenericArray<u8, <D as Digest>::OutputSize>;
