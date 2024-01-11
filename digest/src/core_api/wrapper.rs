use super::{
    AlgorithmName, BufferKindUser, ExtendableOutputCore, FixedOutputCore, OutputSizeUser, Reset,
    UpdateCore, XofReaderCoreWrapper,
};
use crate::{
    ExtendableOutput, ExtendableOutputReset, FixedOutput, FixedOutputReset, HashMarker, Update,
};
use block_buffer::BlockBuffer;
use core::{
    convert::TryInto,
    fmt,
    ops::{Add, Sub},
};
use crypto_common::{
    array::{Array, ArraySize},
    typenum::{Diff, IsLess, Le, NonZero, Sum, U1, U256},
    BlockSizeUser, DeserializeStateError, InvalidLength, Key, KeyInit, KeySizeUser, Output,
    SerializableState, SerializedState, SubSerializedStateSize,
};

#[cfg(feature = "mac")]
use crate::MacMarker;
#[cfg(feature = "oid")]
use const_oid::{AssociatedOid, ObjectIdentifier};

/// Wrapper around [`BufferKindUser`].
///
/// It handles data buffering and implements the slice-based traits.
#[derive(Clone, Default)]
pub struct CoreWrapper<T>
where
    T: BufferKindUser,
{
    core: T,
    buffer: BlockBuffer<T::BlockSize, T::BufferKind>,
}

impl<T> HashMarker for CoreWrapper<T> where T: BufferKindUser + HashMarker {}

#[cfg(feature = "mac")]
impl<T> MacMarker for CoreWrapper<T> where T: BufferKindUser + MacMarker {}

// this blanket impl is needed for HMAC
impl<T> BlockSizeUser for CoreWrapper<T>
where
    T: BufferKindUser + HashMarker,
{
    type BlockSize = T::BlockSize;
}

impl<T> CoreWrapper<T>
where
    T: BufferKindUser,
{
    /// Create new wrapper from `core`.
    #[inline]
    pub fn from_core(core: T) -> Self {
        let buffer = Default::default();
        Self { core, buffer }
    }
}

impl<T> KeySizeUser for CoreWrapper<T>
where
    T: BufferKindUser + KeySizeUser,
{
    type KeySize = T::KeySize;
}

impl<T> KeyInit for CoreWrapper<T>
where
    T: BufferKindUser + KeyInit,
{
    #[inline]
    fn new(key: &Key<Self>) -> Self {
        Self {
            core: T::new(key),
            buffer: Default::default(),
        }
    }

    #[inline]
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        Ok(Self {
            core: T::new_from_slice(key)?,
            buffer: Default::default(),
        })
    }
}

impl<T> fmt::Debug for CoreWrapper<T>
where
    T: BufferKindUser + AlgorithmName,
{
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        T::write_alg_name(f)?;
        f.write_str(" { .. }")
    }
}

impl<T> Reset for CoreWrapper<T>
where
    T: BufferKindUser + Reset,
{
    #[inline]
    fn reset(&mut self) {
        self.core.reset();
        self.buffer.reset();
    }
}

impl<T> Update for CoreWrapper<T>
where
    T: BufferKindUser + UpdateCore,
{
    #[inline]
    fn update(&mut self, input: &[u8]) {
        let Self { core, buffer } = self;
        buffer.digest_blocks(input, |blocks| core.update_blocks(blocks));
    }
}

impl<T> OutputSizeUser for CoreWrapper<T>
where
    T: BufferKindUser + OutputSizeUser,
{
    type OutputSize = T::OutputSize;
}

impl<T> FixedOutput for CoreWrapper<T>
where
    T: FixedOutputCore,
{
    #[inline]
    fn finalize_into(mut self, out: &mut Output<Self>) {
        let Self { core, buffer } = &mut self;
        core.finalize_fixed_core(buffer, out);
    }
}

impl<T> FixedOutputReset for CoreWrapper<T>
where
    T: FixedOutputCore + Reset,
{
    #[inline]
    fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
        let Self { core, buffer } = self;
        core.finalize_fixed_core(buffer, out);
        core.reset();
        buffer.reset();
    }
}

impl<T> ExtendableOutput for CoreWrapper<T>
where
    T: ExtendableOutputCore,
{
    type Reader = XofReaderCoreWrapper<T::ReaderCore>;

    #[inline]
    fn finalize_xof(mut self) -> Self::Reader {
        Self::Reader {
            core: self.core.finalize_xof_core(&mut self.buffer),
            buffer: Default::default(),
        }
    }
}

impl<T> ExtendableOutputReset for CoreWrapper<T>
where
    T: ExtendableOutputCore + Reset,
{
    #[inline]
    fn finalize_xof_reset(&mut self) -> Self::Reader {
        let Self { core, buffer } = self;
        let reader_core = core.finalize_xof_core(buffer);
        core.reset();
        buffer.reset();
        let buffer = Default::default();
        Self::Reader {
            core: reader_core,
            buffer,
        }
    }
}

impl<T> Drop for CoreWrapper<T>
where
    T: BufferKindUser,
{
    #[inline]
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize;
            self.buffer.zeroize();
            self.output_size.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl<T> zeroize::ZeroizeOnDrop for CoreWrapper<T> where T: BufferKindUser + zeroize::ZeroizeOnDrop {}

#[cfg(feature = "oid")]
impl<T> AssociatedOid for CoreWrapper<T>
where
    T: BufferKindUser + AssociatedOid,
{
    const OID: ObjectIdentifier = T::OID;
}

type CoreWrapperSerializedStateSize<T> =
    Sum<Sum<<T as SerializableState>::SerializedStateSize, U1>, <T as BlockSizeUser>::BlockSize>;

impl<T> SerializableState for CoreWrapper<T>
where
    T: BufferKindUser + SerializableState,
    T::BlockSize: IsLess<U256>,
    Le<T::BlockSize, U256>: NonZero,
    T::SerializedStateSize: Add<U1>,
    Sum<T::SerializedStateSize, U1>: Add<T::BlockSize> + ArraySize,
    CoreWrapperSerializedStateSize<T>: Sub<T::SerializedStateSize> + ArraySize,
    SubSerializedStateSize<CoreWrapperSerializedStateSize<T>, T>: Sub<U1> + ArraySize,
    Diff<SubSerializedStateSize<CoreWrapperSerializedStateSize<T>, T>, U1>: ArraySize,
{
    type SerializedStateSize = CoreWrapperSerializedStateSize<T>;

    fn serialize(&self) -> SerializedState<Self> {
        let serialized_core = self.core.serialize();
        let serialized_pos =
            Array::<u8, U1>::clone_from_slice(&[self.buffer.get_pos().try_into().unwrap()]);
        let serialized_data = self.buffer.clone().pad_with_zeros();

        serialized_core
            .concat(serialized_pos)
            .concat(serialized_data)
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let (serialized_core, remaining_buffer) =
            serialized_state.split_ref::<T::SerializedStateSize>();
        let (serialized_pos, serialized_data) = remaining_buffer.split_ref::<U1>();

        Ok(Self {
            core: T::deserialize(serialized_core)?,
            buffer: BlockBuffer::try_new(&serialized_data[..serialized_pos[0].into()])
                .map_err(|_| DeserializeStateError)?,
        })
    }
}

#[cfg(feature = "std")]
impl<T> std::io::Write for CoreWrapper<T>
where
    T: BufferKindUser + UpdateCore,
{
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
    /// Type wrapped by [`CoreWrapper`].
    type Core;
}

mod sealed {
    pub trait Sealed {}
}

impl<T> sealed::Sealed for CoreWrapper<T> where T: BufferKindUser {}

impl<T> CoreProxy for CoreWrapper<T>
where
    T: BufferKindUser,
{
    type Core = T;
}
