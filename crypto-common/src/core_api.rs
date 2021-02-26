//! Low-level core API traits.
use super::{FixedOutput, FixedOutputReset, Reset, Update};
use block_buffer::DigestBuffer;
use core::fmt;
use generic_array::{ArrayLength, GenericArray};

/// Trait for types which consume data in blocks.
#[cfg(feature = "core-api")]
#[cfg_attr(docsrs, doc(cfg(feature = "core-api")))]
pub trait UpdateCore {
    /// Block size in bytes.
    type BlockSize: ArrayLength<u8>;
    /// Block buffer type over which value operates.
    type Buffer: DigestBuffer<Self::BlockSize>;

    /// Update state using the provided data blocks.
    fn update_blocks(&mut self, blocks: &[GenericArray<u8, Self::BlockSize>]);
}

/// Core trait for hash functions with fixed output size.
#[cfg(feature = "core-api")]
#[cfg_attr(docsrs, doc(cfg(feature = "core-api")))]
pub trait FixedOutputCore: UpdateCore {
    /// Size of result in bytes.
    type OutputSize: ArrayLength<u8>;

    /// Finalize state using remaining data stored in the provided block buffer,
    /// write result into provided array using and leave value in a dirty state.
    fn finalize_fixed_core(
        &mut self,
        buffer: &mut Self::Buffer,
        out: &mut GenericArray<u8, Self::OutputSize>,
    );
}

/// Trait which stores algorithm name constant, used in `Debug` implementations.
pub trait AlgorithmName {
    /// Write algorithm name into `f`.
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result;
}

/// Wrapper around [`UpdateCore`] implementations.
///
/// It handles data buffering and implements the slice-based traits.
#[derive(Clone, Default)]
pub struct CoreWrapper<T: UpdateCore> {
    core: T,
    buffer: T::Buffer,
}

impl<T: UpdateCore> CoreWrapper<T> {
    /// Create new wrapper from `core`.
    #[inline]
    pub fn from_core(core: T) -> Self {
        let buffer = Default::default();
        Self { core, buffer }
    }

    /// Decompose wrapper into inner parts.
    #[inline]
    pub fn decompose(self) -> (T, T::Buffer) {
        let Self { core, buffer } = self;
        (core, buffer)
    }
}

impl<T: UpdateCore + Reset> CoreWrapper<T> {
    /// Apply function to core and buffer, return its result,
    /// and reset core and buffer.
    pub fn apply_reset<V>(&mut self, mut f: impl FnMut(&mut T, &mut T::Buffer) -> V) -> V {
        let Self { core, buffer } = self;
        let res = f(core, buffer);
        core.reset();
        buffer.reset();
        res
    }
}

impl<T: UpdateCore + AlgorithmName> fmt::Debug for CoreWrapper<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        T::write_alg_name(f)?;
        f.write_str(" { .. }")
    }
}

impl<D: Reset + UpdateCore> Reset for CoreWrapper<D> {
    #[inline]
    fn reset(&mut self) {
        self.core.reset();
        self.buffer.reset();
    }
}

impl<D: UpdateCore> Update for CoreWrapper<D> {
    #[inline]
    fn update(&mut self, input: &[u8]) {
        let Self { core, buffer } = self;
        buffer.digest_blocks(input, |blocks| core.update_blocks(blocks));
    }
}

impl<D: FixedOutputCore> FixedOutput for CoreWrapper<D> {
    type OutputSize = D::OutputSize;

    #[inline]
    fn finalize_into(mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
        let Self { core, buffer } = &mut self;
        core.finalize_fixed_core(buffer, out);
    }
}

impl<D: FixedOutputCore + Reset> FixedOutputReset for CoreWrapper<D> {
    #[inline]
    fn finalize_into_reset(&mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
        self.apply_reset(|core, buffer| core.finalize_fixed_core(buffer, out));
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl<D: UpdateCore> std::io::Write for CoreWrapper<D> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Update::update(self, buf);
        Ok(buf.len())
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
