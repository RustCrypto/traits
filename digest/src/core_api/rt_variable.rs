use super::{AlgorithmName, BlockSizeUser, TruncSide, UpdateCore, VariableOutputCore};
#[cfg(feature = "mac")]
use crate::MacMarker;
use crate::{HashMarker, InvalidBufferSize};
use crate::{InvalidOutputSize, Reset, Update, VariableOutput, VariableOutputReset};
use block_buffer::BlockBuffer;
use core::{
    convert::TryInto,
    fmt,
    ops::{Add, Sub},
};
use crypto_common::{
    array::{ArraySize, ByteArray},
    typenum::{Diff, IsLess, Le, NonZero, Sum, Unsigned, U1, U256},
    DeserializeStateError, SerializableState, SerializedState,
};

/// Wrapper around [`VariableOutputCore`] which selects output size
/// at run time.
#[derive(Clone)]
pub struct RtVariableCoreWrapper<T>
where
    T: VariableOutputCore,
{
    core: T,
    buffer: BlockBuffer<T::BlockSize, T::BufferKind>,
    output_size: usize,
}

impl<T> RtVariableCoreWrapper<T>
where
    T: VariableOutputCore,
{
    #[inline]
    fn finalize_dirty(&mut self, out: &mut [u8]) -> Result<(), InvalidBufferSize> {
        let Self {
            core,
            buffer,
            output_size,
        } = self;
        if out.len() != *output_size || out.len() > Self::MAX_OUTPUT_SIZE {
            return Err(InvalidBufferSize);
        }
        let mut full_res = Default::default();
        core.finalize_variable_core(buffer, &mut full_res);
        let n = out.len();
        let m = full_res.len() - n;
        match T::TRUNC_SIDE {
            TruncSide::Left => out.copy_from_slice(&full_res[..n]),
            TruncSide::Right => out.copy_from_slice(&full_res[m..]),
        }
        Ok(())
    }
}

impl<T> HashMarker for RtVariableCoreWrapper<T> where T: VariableOutputCore + HashMarker {}

#[cfg(feature = "mac")]
#[cfg_attr(docsrs, doc(cfg(feature = "mac")))]
impl<T> MacMarker for RtVariableCoreWrapper<T> where T: VariableOutputCore + MacMarker {}

impl<T> BlockSizeUser for RtVariableCoreWrapper<T>
where
    T: VariableOutputCore,
    T::BlockSize: IsLess<U256>,
    Le<T::BlockSize, U256>: NonZero,
{
    type BlockSize = T::BlockSize;
}

impl<T> Reset for RtVariableCoreWrapper<T>
where
    T: VariableOutputCore + UpdateCore + Reset,
{
    #[inline]
    fn reset(&mut self) {
        self.buffer.reset();
        self.core.reset();
    }
}

impl<T> Update for RtVariableCoreWrapper<T>
where
    T: VariableOutputCore + UpdateCore,
{
    #[inline]
    fn update(&mut self, input: &[u8]) {
        let Self { core, buffer, .. } = self;
        buffer.digest_blocks(input, |blocks| core.update_blocks(blocks));
    }
}

impl<T> VariableOutput for RtVariableCoreWrapper<T>
where
    T: VariableOutputCore + UpdateCore,
{
    const MAX_OUTPUT_SIZE: usize = T::OutputSize::USIZE;

    fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
        let buffer = Default::default();
        T::new(output_size).map(|core| Self {
            core,
            buffer,
            output_size,
        })
    }

    fn output_size(&self) -> usize {
        self.output_size
    }

    fn finalize_variable(mut self, out: &mut [u8]) -> Result<(), InvalidBufferSize> {
        self.finalize_dirty(out)
    }
}

impl<T> VariableOutputReset for RtVariableCoreWrapper<T>
where
    T: VariableOutputCore + UpdateCore + Reset,
{
    fn finalize_variable_reset(&mut self, out: &mut [u8]) -> Result<(), InvalidBufferSize> {
        self.finalize_dirty(out)?;
        self.core.reset();
        self.buffer.reset();
        Ok(())
    }
}

impl<T> fmt::Debug for RtVariableCoreWrapper<T>
where
    T: VariableOutputCore + UpdateCore + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        T::write_alg_name(f)?;
        f.write_str(" { .. }")
    }
}

impl<T> SerializableState for RtVariableCoreWrapper<T>
where
    T: VariableOutputCore + UpdateCore + SerializableState,
    T::BlockSize: IsLess<U256>,
    Le<T::BlockSize, U256>: NonZero,
    T::SerializedStateSize: Add<U1>,
    Sum<T::SerializedStateSize, U1>: Add<T::BlockSize> + ArraySize,
    Sum<Sum<T::SerializedStateSize, U1>, T::BlockSize>: Add<U1> + ArraySize,
    Sum<Sum<Sum<T::SerializedStateSize, U1>, T::BlockSize>, U1>:
        Sub<T::SerializedStateSize> + ArraySize,
    Diff<Sum<Sum<Sum<T::SerializedStateSize, U1>, T::BlockSize>, U1>, T::SerializedStateSize>:
        Sub<U1> + ArraySize,
    Diff<
        Diff<Sum<Sum<Sum<T::SerializedStateSize, U1>, T::BlockSize>, U1>, T::SerializedStateSize>,
        U1,
    >: Sub<T::BlockSize> + ArraySize,
    Diff<
        Diff<
            Diff<
                Sum<Sum<Sum<T::SerializedStateSize, U1>, T::BlockSize>, U1>,
                T::SerializedStateSize,
            >,
            U1,
        >,
        T::BlockSize,
    >: ArraySize,
{
    type SerializedStateSize = Sum<Sum<Sum<T::SerializedStateSize, U1>, T::BlockSize>, U1>;

    fn serialize(&self) -> SerializedState<Self> {
        let serialized_core = self.core.serialize();
        let serialized_pos =
            ByteArray::<U1>::clone_from_slice(&[self.buffer.get_pos().try_into().unwrap()]);
        let serialized_data = self.buffer.clone().pad_with_zeros();
        let serialized_output_size =
            ByteArray::<U1>::clone_from_slice(&[self.output_size.try_into().unwrap()]);

        serialized_core
            .concat(serialized_pos)
            .concat(serialized_data)
            .concat(serialized_output_size)
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let (serialized_core, remaining_buffer) =
            serialized_state.split_ref::<T::SerializedStateSize>();
        let (serialized_pos, remaining_buffer) = remaining_buffer.split_ref::<U1>();
        let (serialized_data, serialized_output_size) =
            remaining_buffer.split_ref::<T::BlockSize>();

        Ok(Self {
            core: T::deserialize(serialized_core)?,
            buffer: BlockBuffer::try_new(&serialized_data[..serialized_pos[0].into()])
                .map_err(|_| DeserializeStateError)?,
            output_size: serialized_output_size[0].into(),
        })
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl<T> std::io::Write for RtVariableCoreWrapper<T>
where
    T: VariableOutputCore + UpdateCore,
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
