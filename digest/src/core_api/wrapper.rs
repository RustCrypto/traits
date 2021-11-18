use super::{
    AlgorithmName, Buffer, BufferKindUser, ExtendableOutputCore, FixedOutputCore, OutputSizeUser,
    Reset, UpdateCore, XofReaderCoreWrapper,
};
use crate::{ExtendableOutput, FixedOutput, FixedOutputReset, HashMarker, Update};
use block_buffer::BlockBuffer;
use core::fmt;
use crypto_common::{InvalidLength, Key, KeyInit, KeySizeUser, Output};

#[cfg(feature = "mac")]
use crate::MacMarker;

/// Wrapper around [`BufferKindUser`].
///
/// It handles data buffering and implements the slice-based traits.
#[derive(Clone, Default)]
pub struct CoreWrapper<T: BufferKindUser> {
    core: T,
    buffer: BlockBuffer<T::BlockSize, T::BufferKind>,
}

impl<T: HashMarker + BufferKindUser> HashMarker for CoreWrapper<T> {}

#[cfg(feature = "mac")]
impl<T: MacMarker + BufferKindUser> MacMarker for CoreWrapper<T> {}

impl<T: BufferKindUser> CoreWrapper<T> {
    /// Create new wrapper from `core`.
    #[inline]
    pub fn from_core(core: T) -> Self {
        let buffer = Default::default();
        Self { core, buffer }
    }

    /// Decompose wrapper into inner parts.
    #[inline]
    pub fn decompose(self) -> (T, Buffer<T>) {
        let Self { core, buffer } = self;
        (core, buffer)
    }
}

impl<T: KeySizeUser + BufferKindUser> KeySizeUser for CoreWrapper<T> {
    type KeySize = T::KeySize;
}

impl<T: BufferKindUser + KeyInit> KeyInit for CoreWrapper<T> {
    fn new(key: &Key<Self>) -> Self {
        Self {
            core: T::new(key),
            buffer: Default::default(),
        }
    }

    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        Ok(Self {
            core: T::new_from_slice(key)?,
            buffer: Default::default(),
        })
    }
}

impl<T: BufferKindUser + AlgorithmName> fmt::Debug for CoreWrapper<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        T::write_alg_name(f)?;
        f.write_str(" { .. }")
    }
}

impl<D: Reset + BufferKindUser> Reset for CoreWrapper<D> {
    #[inline]
    fn reset(&mut self) {
        self.core.reset();
        self.buffer.reset();
    }
}

impl<D: UpdateCore + BufferKindUser> Update for CoreWrapper<D> {
    #[inline]
    fn update(&mut self, input: &[u8]) {
        let Self { core, buffer } = self;
        buffer.digest_blocks(input, |blocks| core.update_blocks(blocks));
    }
}

impl<D: OutputSizeUser + BufferKindUser> OutputSizeUser for CoreWrapper<D> {
    type OutputSize = D::OutputSize;
}

impl<D: FixedOutputCore> FixedOutput for CoreWrapper<D> {
    #[inline]
    fn finalize_into(mut self, out: &mut Output<Self>) {
        let Self { core, buffer } = &mut self;
        core.finalize_fixed_core(buffer, out);
    }
}

impl<D: FixedOutputCore + Reset> FixedOutputReset for CoreWrapper<D> {
    #[inline]
    fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
        let Self { core, buffer } = self;
        core.finalize_fixed_core(buffer, out);
        core.reset();
        buffer.reset();
    }
}

impl<D: ExtendableOutputCore + Reset> ExtendableOutput for CoreWrapper<D> {
    type Reader = XofReaderCoreWrapper<D::ReaderCore>;

    #[inline]
    fn finalize_xof(self) -> Self::Reader {
        let (mut core, mut buffer) = self.decompose();
        let core = core.finalize_xof_core(&mut buffer);
        let buffer = Default::default();
        Self::Reader { core, buffer }
    }

    #[inline]
    fn finalize_xof_reset(&mut self) -> Self::Reader {
        let Self { core, buffer } = self;
        let core = core.finalize_xof_core(buffer);
        let buffer = Default::default();
        Self::Reader { core, buffer }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl<D: UpdateCore + BufferKindUser> std::io::Write for CoreWrapper<D> {
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

/// A proxy trait to a core type implemented by [`CoreWrapper`]
// TODO: replace with an inherent associated type on stabilization:
// https://github.com/rust-lang/rust/issues/8995
pub trait CoreProxy: sealed::Sealed {
    type Core;
}

mod sealed {
    pub trait Sealed {}
}

impl<T: BufferKindUser> sealed::Sealed for CoreWrapper<T> {}

impl<T: BufferKindUser> CoreProxy for CoreWrapper<T> {
    type Core = T;
}
