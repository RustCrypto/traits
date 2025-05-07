/// Creates a newtype wrapper around another type and
/// delegates implementation of `digest` traits to it.
#[macro_export]
macro_rules! newtype_fixed_hash {
    (
        $(#[$attr:meta])*
        $v:vis struct $name:ident$(<$gp:ident: $bound:ident>)?($core_ty:ty);
    ) => {
        $(#[$attr])*
        $v struct $name$(<$gp: $bound>)? {
            core: $core_ty,
            buffer: $crate::core_api::Buffer<$core_ty>,
        }

        impl$(<$gp: $bound>)? core::fmt::Debug for $name$(<$gp>)? {
            #[inline]
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }

        impl$(<$gp: $bound>)? $crate::crypto_common::AlgorithmName for $name$(<$gp>)? {
            #[inline]
            fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
                <$core_ty as $crate::crypto_common::AlgorithmName>::write_alg_name(f)
            }
        }

        impl$(<$gp: $bound>)? Clone for $name$(<$gp>)? {
            #[inline]
            fn clone(&self) -> Self {
                Self {
                    core: Clone::clone(&self.core),
                    buffer: Clone::clone(&self.buffer),
                }
            }
        }

        impl$(<$gp: $bound>)? Default for $name$(<$gp>)? {
            #[inline]
            fn default() -> Self {
                Self {
                    core: Default::default(),
                    buffer: Default::default(),
                }
            }
        }

        impl$(<$gp: $bound>)? $crate::Reset for $name$(<$gp>)? {
            #[inline]
            fn reset(&mut self) {
                $crate::Reset::reset(&mut self.core);
                self.buffer.reset();
            }
        }

        impl$(<$gp: $bound>)? $crate::core_api::BlockSizeUser for $name$(<$gp>)? {
            type BlockSize = <$core_ty as $crate::crypto_common::BlockSizeUser>::BlockSize;
        }

        impl$(<$gp: $bound>)? $crate::OutputSizeUser for $name$(<$gp>)? {
            type OutputSize = <$core_ty as $crate::core_api::OutputSizeUser>::OutputSize;
        }

        impl$(<$gp: $bound>)? $crate::HashMarker for $name$(<$gp>)? {}

        // Verify that `$core_ty` implements `HashMarker`
        const _: () = {
            fn check$(<$gp: $bound>)?(v: &$core_ty) {
                v as &dyn $crate::HashMarker;
            }
        };

        impl$(<$gp: $bound>)? $crate::core_api::CoreProxy for $name$(<$gp>)? {
            type Core = $core_ty;
        }

        impl$(<$gp: $bound>)? $crate::Update for $name$(<$gp>)? {
            #[inline]
            fn update(&mut self, data: &[u8]) {
                let Self { core, buffer } = self;
                buffer.digest_blocks(data, |blocks| {
                    $crate::core_api::UpdateCore::update_blocks(core, blocks)
                });
            }
        }

        impl$(<$gp: $bound>)? $crate::FixedOutput for $name$(<$gp>)? {
            #[inline]
            fn finalize_into(mut self, out: &mut $crate::Output<Self>) {
                let Self { core, buffer } = &mut self;
                $crate::core_api::FixedOutputCore::finalize_fixed_core(core, buffer, out);
            }
        }

        impl$(<$gp: $bound>)? $crate::FixedOutputReset for $name$(<$gp>)? {
            #[inline]
            fn finalize_into_reset(&mut self, out: &mut $crate::Output<Self>) {
                let Self { core, buffer } = self;
                $crate::core_api::FixedOutputCore::finalize_fixed_core(core, buffer, out);
                $crate::Reset::reset(self);
            }
        }

        impl$(<$gp: $bound>)? $crate::crypto_common::hazmat::SerializableState for $name$(<$gp>)? {
            type SerializedStateSize = $crate::typenum::Sum<
                <$core_ty as $crate::crypto_common::hazmat::SerializableState>::SerializedStateSize,
                $crate::typenum::Add1<
                    <$core_ty as $crate::core_api::BlockSizeUser>::BlockSize
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
                    .split_ref::<<$core_ty as SerializableState>::SerializedStateSize>();
                let (serialized_pos, serialized_data) = remaining_buffer.split_ref::<U1>();

                Ok(Self {
                    core: <$core_ty as SerializableState>::deserialize(serialized_core)?,
                    buffer: BlockBuffer::try_new(&serialized_data[..serialized_pos[0].into()])
                        .map_err(|_| DeserializeStateError)?,
                })
            }
        }
    };

    (
        $(#[$attr:meta])*
        $v:vis struct $name:ident$(<$gp:ident: $bound:ident>)?($core_ty:ty);
        oid: $oid:literal
    ) => {
        $crate::newtype_fixed_hash!(
            $(#[$attr])*
            $v struct $name$(<$gp: $bound>)?($core_ty);
        );

        #[cfg(feature = "oid")]
        impl$(<$gp: $bound>)? $crate::const_oid::AssociatedOid for $name$(<$gp>)? {
            const OID: $crate::const_oid::ObjectIdentifier =
                $crate::const_oid::ObjectIdentifier::new_unwrap($oid);
        }
    };
}
