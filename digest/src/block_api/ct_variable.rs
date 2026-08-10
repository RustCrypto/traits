use super::{
    AlgorithmName, Buffer, BufferKindUser, FixedOutputCore, Reset, TruncSide, UpdateCore,
    VariableOutputCore, VariableOutputCoreCustomized,
};
#[cfg(feature = "mac")]
use crate::MacMarker;
use crate::{CollisionResistance, CustomizedInit, HashMarker};
use common::{
    Block, BlockSizeUser, OutputSizeUser,
    array::{Array, ArraySize},
    hazmat::{DeserializeStateError, SerializableState, SerializedState},
    typenum::{IsLessOrEqual, True},
};
use core::{fmt, marker::PhantomData};

#[cfg(feature = "zeroize")]
struct ScopedFullResult<Size: ArraySize>(Array<u8, Size>);

#[cfg(feature = "zeroize")]
impl<Size: ArraySize> Default for ScopedFullResult<Size> {
    fn default() -> Self {
        Self(Default::default())
    }
}

#[cfg(feature = "zeroize")]
impl<Size: ArraySize> Drop for ScopedFullResult<Size> {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.as_mut_slice().zeroize();
        #[cfg(test)]
        SCOPED_FULL_RESULT_DROPS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(all(test, feature = "zeroize"))]
static SCOPED_FULL_RESULT_DROPS: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Wrapper around [`VariableOutputCore`] which selects output size at compile time.
pub struct CtOutWrapper<T, OutSize>
where
    T: VariableOutputCore,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize, Output = True>,
{
    inner: T,
    _out: PhantomData<OutSize>,
}

impl<T, OutSize> Clone for CtOutWrapper<T, OutSize>
where
    T: VariableOutputCore + Clone,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize, Output = True>,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _out: PhantomData,
        }
    }
}

impl<T, OutSize> HashMarker for CtOutWrapper<T, OutSize>
where
    T: VariableOutputCore + HashMarker,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize, Output = True>,
{
}

#[cfg(feature = "mac")]
impl<T, OutSize> MacMarker for CtOutWrapper<T, OutSize>
where
    T: VariableOutputCore + MacMarker,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize, Output = True>,
{
}

impl<T, OutSize> CollisionResistance for CtOutWrapper<T, OutSize>
where
    T: VariableOutputCore + CollisionResistance,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize, Output = True>,
{
    type CollisionResistance = T::CollisionResistance;
}

impl<T, OutSize> BlockSizeUser for CtOutWrapper<T, OutSize>
where
    T: VariableOutputCore,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize, Output = True>,
{
    type BlockSize = T::BlockSize;
}

impl<T, OutSize> UpdateCore for CtOutWrapper<T, OutSize>
where
    T: VariableOutputCore,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize, Output = True>,
{
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.inner.update_blocks(blocks);
    }
}

impl<T, OutSize> OutputSizeUser for CtOutWrapper<T, OutSize>
where
    T: VariableOutputCore,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize, Output = True>,
{
    type OutputSize = OutSize;
}

impl<T, OutSize> BufferKindUser for CtOutWrapper<T, OutSize>
where
    T: VariableOutputCore,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize, Output = True>,
{
    type BufferKind = T::BufferKind;
}

impl<T, OutSize> FixedOutputCore for CtOutWrapper<T, OutSize>
where
    T: VariableOutputCore,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize, Output = True>,
{
    #[inline]
    fn finalize_fixed_core(
        &mut self,
        buffer: &mut Buffer<Self>,
        out: &mut Array<u8, Self::OutputSize>,
    ) {
        #[cfg(feature = "zeroize")]
        let mut scoped_full_res = ScopedFullResult::<T::OutputSize>::default();
        #[cfg(feature = "zeroize")]
        let full_res = &mut scoped_full_res.0;
        #[cfg(not(feature = "zeroize"))]
        let mut full_res = Default::default();
        #[cfg(not(feature = "zeroize"))]
        let full_res = &mut full_res;
        self.inner.finalize_variable_core(buffer, full_res);
        let n = out.len();
        let m = full_res.len() - n;
        match T::TRUNC_SIDE {
            TruncSide::Left => out.copy_from_slice(&full_res[..n]),
            TruncSide::Right => out.copy_from_slice(&full_res[m..]),
        }
    }
}

#[cfg(all(test, feature = "zeroize"))]
mod tests {
    use super::{SCOPED_FULL_RESULT_DROPS, ScopedFullResult};
    use common::typenum::U32;
    use core::sync::atomic::Ordering;

    extern crate std;

    #[test]
    fn scoped_full_result_zeroizes_on_return_and_unwind() {
        SCOPED_FULL_RESULT_DROPS.store(0, Ordering::SeqCst);
        drop(ScopedFullResult::<U32>::default());
        assert_eq!(SCOPED_FULL_RESULT_DROPS.load(Ordering::SeqCst), 1);

        SCOPED_FULL_RESULT_DROPS.store(0, Ordering::SeqCst);
        let result = std::panic::catch_unwind(|| {
            let _result = ScopedFullResult::<U32>::default();
            panic!("test-only finalization unwind");
        });
        assert!(result.is_err());
        assert_eq!(SCOPED_FULL_RESULT_DROPS.load(Ordering::SeqCst), 1);
    }
}

impl<T, OutSize> Default for CtOutWrapper<T, OutSize>
where
    T: VariableOutputCore,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize, Output = True>,
{
    #[inline]
    fn default() -> Self {
        Self {
            inner: T::new(OutSize::USIZE).unwrap(),
            _out: PhantomData,
        }
    }
}

impl<T, OutSize> CustomizedInit for CtOutWrapper<T, OutSize>
where
    T: VariableOutputCoreCustomized,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize, Output = True>,
{
    #[inline]
    fn new_customized(customization: &[u8]) -> Self {
        Self {
            inner: T::new_customized(customization, OutSize::USIZE),
            _out: PhantomData,
        }
    }
}

impl<T, OutSize> Reset for CtOutWrapper<T, OutSize>
where
    T: VariableOutputCore,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize, Output = True>,
{
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl<T, OutSize> AlgorithmName for CtOutWrapper<T, OutSize>
where
    T: VariableOutputCore + AlgorithmName,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize, Output = True>,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        T::write_alg_name(f)?;
        f.write_str("_")?;
        write!(f, "{}", OutSize::USIZE)
    }
}

#[cfg(feature = "zeroize")]
impl<T, OutSize> zeroize::ZeroizeOnDrop for CtOutWrapper<T, OutSize>
where
    T: VariableOutputCore + zeroize::ZeroizeOnDrop,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize, Output = True>,
{
}

impl<T, OutSize> fmt::Debug for CtOutWrapper<T, OutSize>
where
    T: VariableOutputCore + AlgorithmName,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize, Output = True>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Self::write_alg_name(f)
    }
}

impl<T, OutSize> SerializableState for CtOutWrapper<T, OutSize>
where
    T: VariableOutputCore + SerializableState,
    OutSize: ArraySize + IsLessOrEqual<T::OutputSize, Output = True>,
{
    type SerializedStateSize = <T as SerializableState>::SerializedStateSize;

    fn serialize(&self) -> SerializedState<Self> {
        self.inner.serialize()
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let _out = PhantomData;
        T::deserialize(serialized_state).map(|inner| Self { inner, _out })
    }
}
