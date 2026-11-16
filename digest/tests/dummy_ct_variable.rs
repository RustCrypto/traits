//! Tests against a pseudo-hash with output size selected at compile time.

#![cfg(feature = "block-api")]

mod block_api {
    use core::fmt;
    use digest::{
        HashMarker, InvalidOutputSize, Output, OutputSizeUser,
        block_api::{
            AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, TruncSide, UpdateCore,
            VariableOutputCore, VariableOutputCoreCustomized,
        },
        common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
        consts::U8,
    };

    /// Maximum output size of the test cores in bytes.
    const MAX_OUTPUT_SIZE: usize = 8;

    /// Initial state derived from the requested output size.
    fn seed(output_size: usize) -> u64 {
        u64::try_from(output_size).unwrap_or_default()
    }

    /// Core of primitive XOR hasher with variable output size for testing purposes
    #[derive(Clone, Copy, Debug)]
    pub struct VarHashCore {
        state: u64,
    }

    impl AlgorithmName for VarHashCore {
        fn write_alg_name(f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
            f.write_str("VarHash")
        }
    }

    impl BlockSizeUser for VarHashCore {
        type BlockSize = U8;
    }

    impl BufferKindUser for VarHashCore {
        type BufferKind = block_buffer::Eager;
    }

    impl OutputSizeUser for VarHashCore {
        type OutputSize = U8;
    }

    impl HashMarker for VarHashCore {}

    impl UpdateCore for VarHashCore {
        fn update_blocks(&mut self, blocks: &[Block<Self>]) {
            self.state = blocks
                .iter()
                .fold(self.state, |acc, block| acc ^ u64::from_le_bytes(block.0));
        }
    }

    impl VariableOutputCore for VarHashCore {
        const TRUNC_SIDE: TruncSide = TruncSide::Left;

        fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
            (output_size <= MAX_OUTPUT_SIZE)
                .then(|| Self {
                    state: seed(output_size),
                })
                .ok_or(InvalidOutputSize)
        }

        fn finalize_variable_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
            let block = buffer.pad_with_zeros();
            self.state ^= u64::from_le_bytes(block.0);
            out.copy_from_slice(&self.state.to_le_bytes());
        }
    }

    impl VariableOutputCoreCustomized for VarHashCore {
        fn new_customized(customization: &[u8], output_size: usize) -> Self {
            let state = customization
                .iter()
                .fold(seed(output_size), |acc, &byte| acc ^ u64::from(byte));
            Self { state }
        }
    }

    impl SerializableState for VarHashCore {
        type SerializedStateSize = U8;

        fn serialize(&self) -> SerializedState<Self> {
            self.state.to_le_bytes().into()
        }

        fn deserialize(
            serialized_state: &SerializedState<Self>,
        ) -> Result<Self, DeserializeStateError> {
            Ok(Self {
                state: u64::from_le_bytes(serialized_state.0),
            })
        }
    }

    /// Core of primitive XOR hasher with variable output size which deliberately does *not*
    /// implement `VariableOutputCoreCustomized`, modelling the pre-existing
    /// `buffer_ct_variable!` callers (groestl, kupyna).
    ///
    /// This is a fully independent type rather than a newtype around [`VarHashCore`] on purpose:
    /// a delegating newtype would only type-check while both cores happen to share the same
    /// `BlockSize`/`BufferKind`/`OutputSize`, so the regression guard could rot silently.
    #[derive(Clone, Copy, Debug)]
    pub struct PlainVarHashCore {
        state: u64,
    }

    impl AlgorithmName for PlainVarHashCore {
        fn write_alg_name(f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
            f.write_str("PlainVarHash")
        }
    }

    impl BlockSizeUser for PlainVarHashCore {
        type BlockSize = U8;
    }

    impl BufferKindUser for PlainVarHashCore {
        type BufferKind = block_buffer::Eager;
    }

    impl OutputSizeUser for PlainVarHashCore {
        type OutputSize = U8;
    }

    impl HashMarker for PlainVarHashCore {}

    impl UpdateCore for PlainVarHashCore {
        fn update_blocks(&mut self, blocks: &[Block<Self>]) {
            self.state = blocks
                .iter()
                .fold(self.state, |acc, block| acc ^ u64::from_le_bytes(block.0));
        }
    }

    impl VariableOutputCore for PlainVarHashCore {
        const TRUNC_SIDE: TruncSide = TruncSide::Left;

        fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
            (output_size <= MAX_OUTPUT_SIZE)
                .then(|| Self {
                    state: seed(output_size),
                })
                .ok_or(InvalidOutputSize)
        }

        fn finalize_variable_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
            let block = buffer.pad_with_zeros();
            self.state ^= u64::from_le_bytes(block.0);
            out.copy_from_slice(&self.state.to_le_bytes());
        }
    }

    impl SerializableState for PlainVarHashCore {
        type SerializedStateSize = U8;

        fn serialize(&self) -> SerializedState<Self> {
            self.state.to_le_bytes().into()
        }

        fn deserialize(
            serialized_state: &SerializedState<Self>,
        ) -> Result<Self, DeserializeStateError> {
            Ok(Self {
                state: u64::from_le_bytes(serialized_state.0),
            })
        }
    }
}

use digest::{
    CustomizedInit, FixedOutput, TryCustomizedInit, Update,
    common::hazmat::SerializableState,
    consts::{U4, U8},
};

// The four public call forms of `buffer_ct_variable!`:
// {`exclude:` present, absent} x {`impl:` present, absent}.

digest::buffer_ct_variable!(
    /// Primitive XOR hasher with output size selected at compile time
    pub struct VarHash<OutSize>(block_api::VarHashCore);
    max_size: U8;
    impl: CustomizedInit;
);
digest::buffer_ct_variable!(
    /// Primitive XOR hasher without `SerializableState` support
    pub struct VarHashNoSer<OutSize>(block_api::VarHashCore);
    exclude: SerializableState;
    max_size: U8;
    impl: CustomizedInit;
);
digest::buffer_ct_variable!(
    /// Primitive XOR hasher over a core which does not support customization
    pub struct PlainVarHash<OutSize>(block_api::PlainVarHashCore);
    exclude: SerializableState;
    max_size: U8;
);
digest::buffer_ct_variable!(
    /// Primitive XOR hasher over a core which does not support customization,
    /// with `SerializableState` support
    pub struct PlainVarHashSer<OutSize>(block_api::PlainVarHashCore);
    max_size: U8;
);

/// check for `CustomizedInit` implementations
const _: () = {
    const fn check_customized<T: CustomizedInit + TryCustomizedInit>() {}
    check_customized::<VarHash<U8>>();
    check_customized::<VarHash<U4>>();
    check_customized::<VarHashNoSer<U8>>();
};

#[test]
fn ct_variable_customized_init() {
    // Empty customization string is equivalent to the default initialization
    assert_eq!(
        VarHash::<U8>::new_customized(&[]).finalize_fixed().0,
        VarHash::<U8>::default().finalize_fixed().0,
    );
    // Customization string reaches the core state: 8 ^ 1 ^ 2 == 0x0b
    assert_eq!(
        VarHash::<U8>::new_customized(&[0x01, 0x02])
            .finalize_fixed()
            .0,
        [0x0b, 0, 0, 0, 0, 0, 0, 0],
    );
    // Updates are applied on top of the customized state: 0x0b ^ 0xff == 0xf4
    let mut hasher = VarHash::<U8>::new_customized(&[0x01, 0x02]);
    hasher.update(&[0xff]);
    assert_eq!(hasher.finalize_fixed().0, [0xf4, 0, 0, 0, 0, 0, 0, 0]);
    // Output size reaches the core and the result is truncated: 4 ^ 1 ^ 2 == 0x07
    assert_eq!(
        VarHash::<U4>::new_customized(&[0x01, 0x02])
            .finalize_fixed()
            .0,
        [0x07, 0, 0, 0],
    );
    // The `exclude: SerializableState;` arm generates the same impl
    assert_eq!(
        VarHashNoSer::<U8>::new_customized(&[0x01, 0x02])
            .finalize_fixed()
            .0,
        [0x0b, 0, 0, 0, 0, 0, 0, 0],
    );
}

#[test]
fn ct_variable_customized_init_composes_with_serializable_state() {
    let mut hasher = VarHash::<U8>::new_customized(&[0x01, 0x02]);
    hasher.update(&[0xff]);
    let serialized = hasher.serialize();
    let restored = VarHash::<U8>::deserialize(&serialized).expect("state is valid");
    let restored_out = restored.finalize_fixed();
    assert_eq!(hasher.finalize_fixed(), restored_out);

    // The round trip above is symmetric, so on its own it is also satisfied by a
    // `new_customized` which drops its argument. Pin that the serialized state
    // really was customized by comparing against the uncustomized hasher.
    let mut plain = VarHash::<U8>::default();
    plain.update(&[0xff]);
    assert_ne!(restored_out, plain.finalize_fixed());
}

#[test]
fn ct_variable_without_customization() {
    // Cores which do not implement `VariableOutputCoreCustomized` keep working
    assert_eq!(
        PlainVarHash::<U8>::default().finalize_fixed().0,
        [0x08, 0, 0, 0, 0, 0, 0, 0],
    );
    assert_eq!(
        PlainVarHashSer::<U4>::default().finalize_fixed().0,
        [0x04, 0, 0, 0],
    );
    // The `max_size:`-only arm still emits `SerializableState`
    let mut hasher = PlainVarHashSer::<U8>::default();
    hasher.update(&[0xff]);
    let serialized = hasher.serialize();
    let restored = PlainVarHashSer::<U8>::deserialize(&serialized).expect("state is valid");
    assert_eq!(hasher.finalize_fixed(), restored.finalize_fixed());
}
