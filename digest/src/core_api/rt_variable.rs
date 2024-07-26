use super::{AlgorithmName, BlockSizeUser, TruncSide, VariableOutputCore};
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
    array::{Array, ArraySize},
    hazmat::{DeserializeStateError, SerializableState, SerializedState, SubSerializedStateSize},
    typenum::{Diff, IsLess, Le, NonZero, Sum, Unsigned, U1, U256},
    AddBlockSize, SubBlockSize,
};
#[cfg(feature = "zeroize")]
use zeroize::ZeroizeOnDrop;

/// Wrapper around [`VariableOutputCore`] which selects output size
/// at run time.
#[derive(Clone)]
pub struct RtVariableCoreWrapper<T: VariableOutputCore> {
    core: T,
    buffer: BlockBuffer<T::BlockSize, T::BufferKind>,
    output_size: u8,
}

impl<T: VariableOutputCore> RtVariableCoreWrapper<T> {
    #[inline]
    fn finalize_dirty(&mut self, out: &mut [u8]) -> Result<(), InvalidBufferSize> {
        let Self {
            core,
            buffer,
            output_size,
        } = self;
        let size_u8 = u8::try_from(out.len()).map_err(|_| InvalidBufferSize)?;
        if out.len() > Self::MAX_OUTPUT_SIZE || size_u8 != *output_size {
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

impl<T: VariableOutputCore + HashMarker> HashMarker for RtVariableCoreWrapper<T> {}

#[cfg(feature = "mac")]
impl<T: VariableOutputCore + MacMarker> MacMarker for RtVariableCoreWrapper<T> {}

impl<T: VariableOutputCore> BlockSizeUser for RtVariableCoreWrapper<T> {
    type BlockSize = T::BlockSize;
}

impl<T: VariableOutputCore + Reset> Reset for RtVariableCoreWrapper<T> {
    #[inline]
    fn reset(&mut self) {
        self.buffer.reset();
        self.core.reset();
    }
}

impl<T: VariableOutputCore> Update for RtVariableCoreWrapper<T> {
    #[inline]
    fn update(&mut self, input: &[u8]) {
        let Self { core, buffer, .. } = self;
        buffer.digest_blocks(input, |blocks| core.update_blocks(blocks));
    }
}

impl<T: VariableOutputCore> VariableOutput for RtVariableCoreWrapper<T> {
    const MAX_OUTPUT_SIZE: usize = T::OutputSize::USIZE;

    #[inline]
    fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
        let output_size = u8::try_from(output_size).map_err(|_| InvalidOutputSize)?;
        let buffer = Default::default();
        T::new(output_size.into()).map(|core| Self {
            core,
            buffer,
            output_size,
        })
    }

    #[inline]
    fn output_size(&self) -> usize {
        self.output_size.into()
    }

    #[inline]
    fn finalize_variable(mut self, out: &mut [u8]) -> Result<(), InvalidBufferSize> {
        self.finalize_dirty(out)
    }
}

impl<T: VariableOutputCore + Reset> VariableOutputReset for RtVariableCoreWrapper<T> {
    #[inline]
    fn finalize_variable_reset(&mut self, out: &mut [u8]) -> Result<(), InvalidBufferSize> {
        self.finalize_dirty(out)?;
        self.core.reset();
        self.buffer.reset();
        Ok(())
    }
}

impl<T: VariableOutputCore> Drop for RtVariableCoreWrapper<T> {
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
impl<T: VariableOutputCore + ZeroizeOnDrop> ZeroizeOnDrop for RtVariableCoreWrapper<T> {}

impl<T: VariableOutputCore + AlgorithmName> fmt::Debug for RtVariableCoreWrapper<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        T::write_alg_name(f)?;
        f.write_str(" { .. }")
    }
}

type RtVariableCoreWrapperSerializedStateSize<T> =
    Sum<AddBlockSize<Sum<<T as SerializableState>::SerializedStateSize, U1>, T>, U1>;

impl<T> SerializableState for RtVariableCoreWrapper<T>
where
    T: VariableOutputCore + SerializableState,
    T::BlockSize: IsLess<U256>,
    Le<T::BlockSize, U256>: NonZero,
    T::SerializedStateSize: Add<U1>,
    Sum<T::SerializedStateSize, U1>: Add<T::BlockSize> + ArraySize,
    AddBlockSize<Sum<T::SerializedStateSize, U1>, T>: Add<U1> + ArraySize,
    RtVariableCoreWrapperSerializedStateSize<T>: Sub<T::SerializedStateSize> + ArraySize,
    SubSerializedStateSize<RtVariableCoreWrapperSerializedStateSize<T>, T>: Sub<U1> + ArraySize,
    Diff<SubSerializedStateSize<RtVariableCoreWrapperSerializedStateSize<T>, T>, U1>:
        Sub<T::BlockSize> + ArraySize,
    SubBlockSize<
        Diff<SubSerializedStateSize<RtVariableCoreWrapperSerializedStateSize<T>, T>, U1>,
        T,
    >: ArraySize,
{
    type SerializedStateSize = RtVariableCoreWrapperSerializedStateSize<T>;

    fn serialize(&self) -> SerializedState<Self> {
        let serialized_core = self.core.serialize();
        let serialized_pos = Array([self.buffer.get_pos().try_into().unwrap()]);
        let serialized_data = self.buffer.clone().pad_with_zeros();
        let serialized_output_size = Array([self.output_size]);

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
            output_size: serialized_output_size[0],
        })
    }
}

#[cfg(feature = "std")]
impl<T: VariableOutputCore> std::io::Write for RtVariableCoreWrapper<T> {
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
