use super::{AlgorithmName, FixedOutputCore, Reset, UpdateCore, VariableOutputCore};
use core::{fmt, marker::PhantomData};
use crypto_common::block_buffer::BlockBuffer;
use generic_array::{
    typenum::{IsLessOrEqual, LeEq, NonZero},
    ArrayLength, GenericArray,
};

/// Wrapper around [`VariableOutputCore`] which selects output size
/// at compile time.
#[derive(Clone)]
pub struct CtVariableCoreWrapper<T, OutSize>
where
    T: VariableOutputCore,
    OutSize: ArrayLength<u8> + IsLessOrEqual<T::MaxOutputSize>,
    LeEq<OutSize, T::MaxOutputSize>: NonZero,
{
    inner: T,
    _out: PhantomData<OutSize>,
}

impl<T, OutSize> UpdateCore for CtVariableCoreWrapper<T, OutSize>
where
    T: VariableOutputCore,
    OutSize: ArrayLength<u8> + IsLessOrEqual<T::MaxOutputSize>,
    LeEq<OutSize, T::MaxOutputSize>: NonZero,
{
    type BlockSize = T::BlockSize;

    #[inline]
    fn update_blocks(&mut self, blocks: &[GenericArray<u8, Self::BlockSize>]) {
        self.inner.update_blocks(blocks);
    }
}

impl<T, OutSize> FixedOutputCore for CtVariableCoreWrapper<T, OutSize>
where
    T: VariableOutputCore,
    OutSize: ArrayLength<u8> + IsLessOrEqual<T::MaxOutputSize>,
    LeEq<OutSize, T::MaxOutputSize>: NonZero,
{
    type OutputSize = OutSize;

    #[inline]
    fn finalize_fixed_core(
        &mut self,
        buffer: &mut BlockBuffer<Self::BlockSize>,
        out: &mut GenericArray<u8, Self::OutputSize>,
    ) {
        self.inner
            .finalize_variable_core(buffer, out.len(), |r| out.copy_from_slice(r));
    }
}

impl<T, OutSize> Default for CtVariableCoreWrapper<T, OutSize>
where
    T: VariableOutputCore,
    OutSize: ArrayLength<u8> + IsLessOrEqual<T::MaxOutputSize>,
    LeEq<OutSize, T::MaxOutputSize>: NonZero,
{
    #[inline]
    fn default() -> Self {
        Self {
            inner: T::new(OutSize::USIZE).unwrap(),
            _out: Default::default(),
        }
    }
}

impl<T, OutSize> Reset for CtVariableCoreWrapper<T, OutSize>
where
    T: VariableOutputCore,
    OutSize: ArrayLength<u8> + IsLessOrEqual<T::MaxOutputSize>,
    LeEq<OutSize, T::MaxOutputSize>: NonZero,
{
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl<T, OutSize> AlgorithmName for CtVariableCoreWrapper<T, OutSize>
where
    T: VariableOutputCore + AlgorithmName,
    OutSize: ArrayLength<u8> + IsLessOrEqual<T::MaxOutputSize>,
    LeEq<OutSize, T::MaxOutputSize>: NonZero,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        T::write_alg_name(f)?;
        f.write_str("_")?;
        write!(f, "{}", OutSize::USIZE)
    }
}
