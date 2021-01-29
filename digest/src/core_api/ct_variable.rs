use super::{AlgorithmName, FixedOutputCore, UpdateCore, VariableOutputCore};
use block_buffer::BlockBuffer;
use core::{fmt, marker::PhantomData};
use generic_array::typenum::type_operators::IsLessOrEqual;
use generic_array::{ArrayLength, GenericArray};

/// Wrapper around [`VariableOutputCore`] which selects output size
/// at compile time.
#[derive(Clone)]
pub struct CtVariableWrapper<T, OutSize>
where
    T: VariableOutputCore,
    OutSize: ArrayLength<u8> + IsLessOrEqual<T::MaxOutputSize>,
{
    inner: T,
    _out: PhantomData<OutSize>,
}

impl<T, OutSize> UpdateCore for CtVariableWrapper<T, OutSize>
where
    T: VariableOutputCore,
    OutSize: ArrayLength<u8> + IsLessOrEqual<T::MaxOutputSize>,
{
    type BlockSize = T::BlockSize;

    #[inline]
    fn update_blocks(&mut self, blocks: &[GenericArray<u8, Self::BlockSize>]) {
        self.inner.update_blocks(blocks);
    }
}

impl<T, OutSize> FixedOutputCore for CtVariableWrapper<T, OutSize>
where
    T: VariableOutputCore,
    OutSize: ArrayLength<u8> + IsLessOrEqual<T::MaxOutputSize>,
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

impl<T, OutSize> Default for CtVariableWrapper<T, OutSize>
where
    T: VariableOutputCore,
    OutSize: ArrayLength<u8> + IsLessOrEqual<T::MaxOutputSize>,
{
    #[inline]
    fn default() -> Self {
        Self {
            inner: T::new(OutSize::USIZE).unwrap(),
            _out: Default::default(),
        }
    }
}

impl<T, OutSize> AlgorithmName for CtVariableWrapper<T, OutSize>
where
    T: VariableOutputCore + AlgorithmName,
    OutSize: ArrayLength<u8> + IsLessOrEqual<T::MaxOutputSize>,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        T::write_alg_name(f)?;
        f.write_str("_")?;
        write!(f, "{}", OutSize::USIZE)
    }
}
