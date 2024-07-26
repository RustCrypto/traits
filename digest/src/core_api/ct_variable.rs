use super::{
    AlgorithmName, Buffer, BufferKindUser, FixedOutputCore, Reset, TruncSide, UpdateCore,
    VariableOutputCore,
};
use crate::HashMarker;
#[cfg(feature = "mac")]
use crate::MacMarker;
#[cfg(feature = "oid")]
use const_oid::{AssociatedOid, ObjectIdentifier};
use core::{
    fmt,
    marker::PhantomData,
    ops::{Add, Sub},
};
use crypto_common::{
    array::{Array, ArraySize},
    hazmat::{DeserializeStateError, SerializableState, SerializedState, SubSerializedStateSize},
    typenum::{IsLess, IsLessOrEqual, Le, LeEq, NonZero, Sum, U1, U256},
    Block, BlockSizeUser, OutputSizeUser,
};

/// Dummy type used with [`CtVariableCoreWrapper`] in cases when
/// resulting hash does not have a known OID.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct NoOid;

/// Wrapper around [`VariableOutputCore`] which selects output size
/// at compile time.
#[derive(Clone)]
pub struct CtVariableCoreWrapper<T, OutSize, O = NoOid>
where
    T: VariableOutputCore,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize>,
    LeEq<OutSize, T::OutputSize>: NonZero,
{
    inner: T,
    _out: PhantomData<(OutSize, O)>,
}

impl<T, OutSize, O> HashMarker for CtVariableCoreWrapper<T, OutSize, O>
where
    T: VariableOutputCore + HashMarker,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize>,
    LeEq<OutSize, T::OutputSize>: NonZero,
{
}

#[cfg(feature = "mac")]
impl<T, OutSize, O> MacMarker for CtVariableCoreWrapper<T, OutSize, O>
where
    T: VariableOutputCore + MacMarker,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize>,
    LeEq<OutSize, T::OutputSize>: NonZero,
{
}

impl<T, OutSize, O> BlockSizeUser for CtVariableCoreWrapper<T, OutSize, O>
where
    T: VariableOutputCore,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize>,
    LeEq<OutSize, T::OutputSize>: NonZero,
{
    type BlockSize = T::BlockSize;
}

impl<T, OutSize, O> UpdateCore for CtVariableCoreWrapper<T, OutSize, O>
where
    T: VariableOutputCore,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize>,
    LeEq<OutSize, T::OutputSize>: NonZero,
{
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.inner.update_blocks(blocks);
    }
}

impl<T, OutSize, O> OutputSizeUser for CtVariableCoreWrapper<T, OutSize, O>
where
    T: VariableOutputCore,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize>,
    LeEq<OutSize, T::OutputSize>: NonZero,
{
    type OutputSize = OutSize;
}

impl<T, OutSize, O> BufferKindUser for CtVariableCoreWrapper<T, OutSize, O>
where
    T: VariableOutputCore,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize>,
    LeEq<OutSize, T::OutputSize>: NonZero,
{
    type BufferKind = T::BufferKind;
}

impl<T, OutSize, O> FixedOutputCore for CtVariableCoreWrapper<T, OutSize, O>
where
    T: VariableOutputCore,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize>,
    LeEq<OutSize, T::OutputSize>: NonZero,
{
    #[inline]
    fn finalize_fixed_core(
        &mut self,
        buffer: &mut Buffer<Self>,
        out: &mut Array<u8, Self::OutputSize>,
    ) {
        let mut full_res = Default::default();
        self.inner.finalize_variable_core(buffer, &mut full_res);
        let n = out.len();
        let m = full_res.len() - n;
        match T::TRUNC_SIDE {
            TruncSide::Left => out.copy_from_slice(&full_res[..n]),
            TruncSide::Right => out.copy_from_slice(&full_res[m..]),
        }
    }
}

impl<T, OutSize, O> Default for CtVariableCoreWrapper<T, OutSize, O>
where
    T: VariableOutputCore,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize>,
    LeEq<OutSize, T::OutputSize>: NonZero,
{
    #[inline]
    fn default() -> Self {
        Self {
            inner: T::new(OutSize::USIZE).unwrap(),
            _out: PhantomData,
        }
    }
}

impl<T, OutSize, O> Reset for CtVariableCoreWrapper<T, OutSize, O>
where
    T: VariableOutputCore,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize>,
    LeEq<OutSize, T::OutputSize>: NonZero,
{
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl<T, OutSize, O> AlgorithmName for CtVariableCoreWrapper<T, OutSize, O>
where
    T: VariableOutputCore + AlgorithmName,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize>,
    LeEq<OutSize, T::OutputSize>: NonZero,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        T::write_alg_name(f)?;
        f.write_str("_")?;
        write!(f, "{}", OutSize::USIZE)
    }
}

#[cfg(feature = "oid")]
impl<T, OutSize, O> AssociatedOid for CtVariableCoreWrapper<T, OutSize, O>
where
    T: VariableOutputCore,
    O: AssociatedOid,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize>,
    LeEq<OutSize, T::OutputSize>: NonZero,
{
    const OID: ObjectIdentifier = O::OID;
}

#[cfg(feature = "zeroize")]
impl<T, OutSize, O> zeroize::ZeroizeOnDrop for CtVariableCoreWrapper<T, OutSize, O>
where
    T: VariableOutputCore + zeroize::ZeroizeOnDrop,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize>,
    LeEq<OutSize, T::OutputSize>: NonZero,
{
}

impl<T, OutSize, O> fmt::Debug for CtVariableCoreWrapper<T, OutSize, O>
where
    T: VariableOutputCore + AlgorithmName,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize>,
    LeEq<OutSize, T::OutputSize>: NonZero,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Self::write_alg_name(f)
    }
}

/// Implement dummy type with hidden docs which is used to "carry" hasher
/// OID for [`CtVariableCoreWrapper`].
#[macro_export]
macro_rules! impl_oid_carrier {
    ($name:ident, $oid:literal) => {
        #[doc(hidden)]
        #[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
        pub struct $name;

        #[cfg(feature = "oid")]
        impl AssociatedOid for $name {
            const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap($oid);
        }
    };
}

type CtVariableCoreWrapperSerializedStateSize<T> =
    Sum<<T as SerializableState>::SerializedStateSize, U1>;

impl<T, OutSize, O> SerializableState for CtVariableCoreWrapper<T, OutSize, O>
where
    T: VariableOutputCore + SerializableState,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize>,
    LeEq<OutSize, T::OutputSize>: NonZero,
    T::BlockSize: IsLess<U256>,
    Le<T::BlockSize, U256>: NonZero,
    T::SerializedStateSize: Add<U1>,
    CtVariableCoreWrapperSerializedStateSize<T>: Sub<T::SerializedStateSize> + ArraySize,
    SubSerializedStateSize<CtVariableCoreWrapperSerializedStateSize<T>, T>: ArraySize,
{
    type SerializedStateSize = CtVariableCoreWrapperSerializedStateSize<T>;

    fn serialize(&self) -> SerializedState<Self> {
        let serialized_inner = self.inner.serialize();
        let serialized_outsize = Array([OutSize::U8]);

        serialized_inner.concat(serialized_outsize)
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let (serialized_inner, serialized_outsize) =
            serialized_state.split_ref::<T::SerializedStateSize>();

        if serialized_outsize[0] != OutSize::U8 {
            return Err(DeserializeStateError);
        }

        Ok(Self {
            inner: T::deserialize(serialized_inner)?,
            _out: PhantomData,
        })
    }
}
