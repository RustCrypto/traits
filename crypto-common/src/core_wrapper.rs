//! Low-level core API traits.
use super::{
    AlgorithmName, BufferUser, FixedOutput, FixedOutputCore, FixedOutputReset, KeyInit,
    KeySizeUser, OutputSizeUser, Reset, Update, UpdateCore,
};
use block_buffer::DigestBuffer;
use core::fmt;
use generic_array::GenericArray;

/// Wrapper around [`BufferUser`].
///
/// It handles data buffering and implements the slice-based traits.
#[derive(Clone, Default)]
pub struct CoreWrapper<T: BufferUser> {
    core: T,
    buffer: T::Buffer,
}

impl<T: BufferUser> CoreWrapper<T> {
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

impl<T: BufferUser + Reset> CoreWrapper<T> {
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

impl<T: KeySizeUser + BufferUser> KeySizeUser for CoreWrapper<T> {
    type KeySize = T::KeySize;
}

impl<T: BufferUser + KeyInit> KeyInit for CoreWrapper<T> {
    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        Self {
            core: T::new(key),
            buffer: Default::default(),
        }
    }
}

impl<T: BufferUser + AlgorithmName> fmt::Debug for CoreWrapper<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        T::write_alg_name(f)?;
        f.write_str(" { .. }")
    }
}

impl<D: Reset + BufferUser> Reset for CoreWrapper<D> {
    #[inline]
    fn reset(&mut self) {
        self.core.reset();
        self.buffer.reset();
    }
}

impl<D: UpdateCore + BufferUser> Update for CoreWrapper<D> {
    #[inline]
    fn update(&mut self, input: &[u8]) {
        let Self { core, buffer } = self;
        buffer.digest_blocks(input, |blocks| core.update_blocks(blocks));
    }
}

impl<D: OutputSizeUser + BufferUser> OutputSizeUser for CoreWrapper<D> {
    type OutputSize = D::OutputSize;
}

impl<D: FixedOutputCore> FixedOutput for CoreWrapper<D> {
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
impl<D: UpdateCore + BufferUser> std::io::Write for CoreWrapper<D> {
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
