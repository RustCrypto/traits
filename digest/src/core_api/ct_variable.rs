use super::{
    AlgorithmName, Buffer, BufferKindUser, FixedOutputCore, Reset, TruncSide, UpdateCore,
    VariableOutputCore,
};
#[cfg(feature = "mac")]
use crate::MacMarker;
use crate::{CollisionResistance, CustomizedInit, HashMarker, VarOutputCustomized};
use core::{
    fmt,
    marker::PhantomData,
    ops::{Add, Sub},
};
use crypto_common::{
    Block, BlockSizeUser, OutputSizeUser,
    array::{Array, ArraySize},
    hazmat::{DeserializeStateError, SerializableState, SerializedState, SubSerializedStateSize},
    typenum::{IsLess, IsLessOrEqual, Le, LeEq, NonZero, Sum, U1, U256},
};
/// Wrapper around [`VariableOutputCore`] which selects output size
/// at compile time.
#[derive(Clone)]
pub struct CtVariableCoreWrapper<T, OutSize>
where
    T: VariableOutputCore,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize>,
    LeEq<OutSize, T::OutputSize>: NonZero,
{
    inner: T,
    _out: PhantomData<OutSize>,
}

impl<T, OutSize> HashMarker for CtVariableCoreWrapper<T, OutSize>
where
    T: VariableOutputCore + HashMarker,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize>,
    LeEq<OutSize, T::OutputSize>: NonZero,
{
}

#[cfg(feature = "mac")]
impl<T, OutSize> MacMarker for CtVariableCoreWrapper<T, OutSize>
where
    T: VariableOutputCore + MacMarker,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize>,
    LeEq<OutSize, T::OutputSize>: NonZero,
{
}

impl<T, OutSize> CollisionResistance for CtVariableCoreWrapper<T, OutSize>
where
    T: VariableOutputCore + CollisionResistance,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize>,
    LeEq<OutSize, T::OutputSize>: NonZero,
{
    type CollisionResistance = T::CollisionResistance;
}

impl<T, OutSize> BlockSizeUser for CtVariableCoreWrapper<T, OutSize>
where
    T: VariableOutputCore,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize>,
    LeEq<OutSize, T::OutputSize>: NonZero,
{
    type BlockSize = T::BlockSize;
}

impl<T, OutSize> UpdateCore for CtVariableCoreWrapper<T, OutSize>
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

impl<T, OutSize> OutputSizeUser for CtVariableCoreWrapper<T, OutSize>
where
    T: VariableOutputCore,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize>,
    LeEq<OutSize, T::OutputSize>: NonZero,
{
    type OutputSize = OutSize;
}

impl<T, OutSize> BufferKindUser for CtVariableCoreWrapper<T, OutSize>
where
    T: VariableOutputCore,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize>,
    LeEq<OutSize, T::OutputSize>: NonZero,
{
    type BufferKind = T::BufferKind;
}

impl<T, OutSize> FixedOutputCore for CtVariableCoreWrapper<T, OutSize>
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

impl<T, OutSize> Default for CtVariableCoreWrapper<T, OutSize>
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

impl<T, OutSize> CustomizedInit for CtVariableCoreWrapper<T, OutSize>
where
    T: VariableOutputCore + VarOutputCustomized,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize>,
    LeEq<OutSize, T::OutputSize>: NonZero,
{
    #[inline]
    fn new_customized(customization: &[u8]) -> Self {
        Self {
            inner: T::new_customized(customization, OutSize::USIZE),
            _out: PhantomData,
        }
    }
}

impl<T, OutSize> Reset for CtVariableCoreWrapper<T, OutSize>
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

impl<T, OutSize> AlgorithmName for CtVariableCoreWrapper<T, OutSize>
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

#[cfg(feature = "zeroize")]
impl<T, OutSize> zeroize::ZeroizeOnDrop for CtVariableCoreWrapper<T, OutSize>
where
    T: VariableOutputCore + zeroize::ZeroizeOnDrop,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize>,
    LeEq<OutSize, T::OutputSize>: NonZero,
{
}

impl<T, OutSize> fmt::Debug for CtVariableCoreWrapper<T, OutSize>
where
    T: VariableOutputCore + AlgorithmName,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize>,
    LeEq<OutSize, T::OutputSize>: NonZero,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Self::write_alg_name(f)
    }
}

type CtVariableCoreWrapperSerializedStateSize<T> =
    Sum<<T as SerializableState>::SerializedStateSize, U1>;

impl<T, OutSize> SerializableState for CtVariableCoreWrapper<T, OutSize>
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
