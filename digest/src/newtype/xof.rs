/// Creates a newtype wrapper around another type and
/// delegates implementation of `digest` traits to it.
#[macro_export]
macro_rules! newtype_xof_hash {
    (
        $(#[$attr:meta])*
        $hasher_vis:vis struct $hasher_name:ident($hasher_core:ty);
        $(#[$reader_attr:meta])*
        $reader_vis:vis struct $reader_name:ident($reader_core:ty);
        $(oid: $oid:literal;)?
    ) => {
        $(#[$attr])*
        $hasher_vis struct $hasher_name {
            core: $hasher_core,
            buffer: $crate::core_api::Buffer<$hasher_core>,
        }

        impl core::fmt::Debug for $hasher_name {
            #[inline]
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($hasher_name), " { ... }"))
            }
        }

        impl $crate::crypto_common::AlgorithmName for $hasher_name {
            #[inline]
            fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
                <$hasher_core as $crate::crypto_common::AlgorithmName>::write_alg_name(f)
            }
        }

        impl Clone for $hasher_name {
            #[inline]
            fn clone(&self) -> Self {
                Self {
                    core: Clone::clone(&self.core),
                    buffer: Clone::clone(&self.buffer),
                }
            }
        }

        impl Default for $hasher_name {
            #[inline]
            fn default() -> Self {
                Self {
                    core: Default::default(),
                    buffer: Default::default(),
                }
            }
        }

        impl $crate::Reset for $hasher_name {
            #[inline]
            fn reset(&mut self) {
                $crate::Reset::reset(&mut self.core);
                self.buffer.reset();
            }
        }

        impl $crate::core_api::BlockSizeUser for $hasher_name {
            type BlockSize = <$hasher_core as $crate::crypto_common::BlockSizeUser>::BlockSize;
        }

        impl $crate::HashMarker for $hasher_name {}

        // Verify that `$hasher_core` implements `HashMarker`
        const _: () = {
            fn check(v: &$hasher_core) {
                v as &dyn $crate::HashMarker;
            }
        };

        impl $crate::core_api::CoreProxy for $hasher_name {
            type Core = $hasher_core;
        }

        impl $crate::Update for $hasher_name {
            #[inline]
            fn update(&mut self, data: &[u8]) {
                let Self { core, buffer } = self;
                buffer.digest_blocks(data, |blocks| {
                    $crate::core_api::UpdateCore::update_blocks(core, blocks)
                });
            }
        }

        impl $crate::ExtendableOutput for $hasher_name {
            type Reader = $reader_name;

            #[inline]
            fn finalize_xof(mut self) -> Self::Reader {
                let Self { core, buffer } = &mut self;
                let core = <$hasher_core as $crate::core_api::ExtendableOutputCore>::finalize_xof_core(core, buffer);
                let buffer = Default::default();
                Self::Reader { core, buffer }
            }
        }

        impl $crate::ExtendableOutputReset for $hasher_name {
            #[inline]
            fn finalize_xof_reset(&mut self) -> Self::Reader {
                let Self { core, buffer } = self;
                let core = <$hasher_core as $crate::core_api::ExtendableOutputCore>::finalize_xof_core(core, buffer);
                $crate::Reset::reset(self);
                let buffer = Default::default();
                Self::Reader { core, buffer }
            }
        }


        impl $crate::crypto_common::hazmat::SerializableState for $hasher_name {
            type SerializedStateSize = $crate::typenum::Sum<
                <$hasher_core as $crate::crypto_common::hazmat::SerializableState>::SerializedStateSize,
                $crate::typenum::Add1<
                    <$hasher_core as $crate::core_api::BlockSizeUser>::BlockSize
                >
            >;

            #[inline]
            fn serialize(&self) -> $crate::crypto_common::hazmat::SerializedState<Self> {
                use $crate::{
                    array::Array,
                    consts::U1,
                    block_buffer::BlockBuffer,
                    crypto_common::hazmat::SerializableState,
                };

                let serialized_core = self.core.serialize();
                let pos = u8::try_from(self.buffer.get_pos()).unwrap();
                let serialized_pos: Array<u8, U1> = Array([pos]);
                let serialized_data = self.buffer.clone().pad_with_zeros();

                serialized_core
                    .concat(serialized_pos)
                    .concat(serialized_data)
            }

            #[inline]
            fn deserialize(
                serialized_state: &$crate::crypto_common::hazmat::SerializedState<Self>,
            ) -> Result<Self, $crate::crypto_common::hazmat::DeserializeStateError> {
                use $crate::{
                    block_buffer::BlockBuffer,
                    consts::U1,
                    crypto_common::hazmat::{SerializableState, DeserializeStateError},
                };

                let (serialized_core, remaining_buffer) = serialized_state
                    .split_ref::<<$hasher_core as SerializableState>::SerializedStateSize>();
                let (serialized_pos, serialized_data) = remaining_buffer.split_ref::<U1>();

                Ok(Self {
                    core: <$hasher_core as SerializableState>::deserialize(serialized_core)?,
                    buffer: BlockBuffer::try_new(&serialized_data[..serialized_pos[0].into()])
                        .map_err(|_| DeserializeStateError)?,
                })
            }
        }

        $(
            #[cfg(feature = "oid")]
            impl $crate::const_oid::AssociatedOid for $hasher_name {
                const OID: $crate::const_oid::ObjectIdentifier =
                    $crate::const_oid::ObjectIdentifier::new_unwrap($oid);
            }
        )?

        $(#[$reader_attr])*
        $reader_vis struct $reader_name {
            core: $reader_core,
            buffer: $crate::block_buffer::ReadBuffer<<$reader_core as $crate::core_api::BlockSizeUser>::BlockSize>,
        }

        impl core::fmt::Debug for $reader_name {
            #[inline]
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($reader_name), " { ... }"))
            }
        }

        impl Clone for $reader_name {
            #[inline]
            fn clone(&self) -> Self {
                Self {
                    core: Clone::clone(&self.core),
                    buffer: Clone::clone(&self.buffer),
                }
            }
        }

        impl $crate::XofReader for $reader_name {
            #[inline]
            fn read(&mut self, buf: &mut [u8]) {
                let Self { core, buffer } = self;
                buffer.read(buf, |block| {
                    *block = $crate::core_api::XofReaderCore::read_block(core);
                });
            }
        }
    };
}
