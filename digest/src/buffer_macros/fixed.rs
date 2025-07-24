/// Creates a buffered wrapper around block-level "core" type which implements fixed output size traits.
#[macro_export]
macro_rules! buffer_fixed {
    (
        $(#[$attr:meta])*
        $v:vis struct $name:ident
        $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
        ($core_ty:ty);
        impl: $($trait_name:ident)*;
    ) => {
        $(#[$attr])*
        $v struct $name$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? {
            core: $core_ty,
            buffer: $crate::block_api::Buffer<$core_ty>,
        }

        $crate::buffer_fixed!(
            impl_inner: $name$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?($core_ty);
            $($trait_name)*;
        );
    };

    (
        $(#[$attr:meta])*
        $v:vis struct $name:ident
        $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
        ($core_ty:ty);
        oid: $oid:literal;
        impl: $($trait_name:ident)*;
    ) => {
        $crate::buffer_fixed!(
            $(#[$attr])*
            $v struct $name$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?($core_ty);
            impl: $($trait_name)*;
        );

        #[cfg(feature = "oid")]
        impl$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? $crate::const_oid::AssociatedOid for $name$(< $( $lt ),+ >)? {
            const OID: $crate::const_oid::ObjectIdentifier =
                $crate::const_oid::ObjectIdentifier::new_unwrap($oid);
        }

        impl$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? Drop for $name$(< $( $lt ),+ >)? {
            #[inline]
            fn drop(&mut self) {
                #[cfg(feature = "zeroize")]
                {
                    use $crate::zeroize::Zeroize;
                    self.core.zeroize();
                    self.buffer.zeroize();
                }
            }
        }

        #[cfg(feature = "zeroize")]
        impl$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? $crate::zeroize::ZeroizeOnDrop for $name$(< $( $lt ),+ >)? {}
    };

    // Terminates `impl_inner` sequences.
    (
        impl_inner: $name:ident
        $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
        ($core_ty:ty);
        ;
    ) => {};

    // Implements the set of traits common for fixed output hashes:
    // `Default`, `Clone`, `HashMarker`, `Reset`, `FixedOutputReset`, `SerializableState`
    (
        impl_inner: $name:ident
        $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
        ($core_ty:ty);
        FixedHashTraits $($trait_name:ident)*;
    ) => {
        $crate::buffer_fixed!(
            impl_inner: $name$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?($core_ty);
            BaseFixedTraits AlgorithmName Default Clone HashMarker
            Reset FixedOutputReset SerializableState $($trait_name)*;
        );
    };

    // Implements the set of traits common for MAC functions:
    // `Debug`, `BlockSizeUser`, `OutputSizeUser`, `CoreProxy`, `Update`, `FixedOutput`,
    // `Clone`, `MacMarker`.
    (
        impl_inner: $name:ident
        $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
        ($core_ty:ty);
        MacTraits $($trait_name:ident)*;
    ) => {
        $crate::buffer_fixed!(
            impl_inner: $name$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?($core_ty);
            BaseFixedTraits Clone MacMarker $($trait_name)*;
        );
    };

    // Implements the set of traits common for resettable MAC functions:
    // `Debug`, `BlockSizeUser`, `OutputSizeUser`, `CoreProxy`, `Update`, `FixedOutput`,
    // `Clone`, `MacMarker`, `Reset`, `FixedOutputReset`.
    (
        impl_inner: $name:ident
        $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
        ($core_ty:ty);
        ResetMacTraits $($trait_name:ident)*;
    ) => {
        $crate::buffer_fixed!(
            impl_inner: $name$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?($core_ty);
            MacTraits Reset FixedOutputReset $($trait_name)*;
        );
    };

    // Implements basic fixed traits:
    // `Debug`, `BlockSizeUser`, `OutputSizeUser`, `CoreProxy`, `Update`, and `FixedOutput`.
    (
        impl_inner: $name:ident
        $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
        ($core_ty:ty);
        BaseFixedTraits $($trait_name:ident)*;
    ) => {
        $crate::buffer_fixed!(
            impl_inner: $name$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?($core_ty);
            Debug BlockSizeUser OutputSizeUser CoreProxy Update FixedOutput $($trait_name)*;
        );
    };

    // Implements `Debug`
    (
        impl_inner: $name:ident
        $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
        ($core_ty:ty);
        Debug $($trait_name:ident)*;
    ) => {
        impl$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? core::fmt::Debug for $name$(< $( $lt ),+ >)? {
            #[inline]
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }

        $crate::buffer_fixed!(impl_inner: $name$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?($core_ty); $($trait_name)*;);
    };

    // Implements `AlgorithmName`
    (
        impl_inner: $name:ident
        $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
        ($core_ty:ty);
        AlgorithmName $($trait_name:ident)*;
    ) => {
        impl$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? $crate::crypto_common::AlgorithmName for $name$(< $( $lt ),+ >)? {
            #[inline]
            fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
                <$core_ty as $crate::crypto_common::AlgorithmName>::write_alg_name(f)
            }
        }

        $crate::buffer_fixed!(impl_inner: $name$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?($core_ty); $($trait_name)*;);
    };

    // Implements `BlockSizeUser`
    (
        impl_inner: $name:ident
        $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
        ($core_ty:ty);
        BlockSizeUser $($trait_name:ident)*;
    ) => {
        impl$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? $crate::block_api::BlockSizeUser for $name$(< $( $lt ),+ >)? {
            type BlockSize = <$core_ty as $crate::crypto_common::BlockSizeUser>::BlockSize;
        }

        $crate::buffer_fixed!(impl_inner: $name$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?($core_ty); $($trait_name)*;);
    };

    // Implements `OutputSizeUser`
    (
        impl_inner: $name:ident
        $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
        ($core_ty:ty);
        OutputSizeUser $($trait_name:ident)*;
    ) => {
        impl$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? $crate::OutputSizeUser for $name$(< $( $lt ),+ >)? {
            type OutputSize = <$core_ty as $crate::block_api::OutputSizeUser>::OutputSize;
        }

        $crate::buffer_fixed!(impl_inner: $name$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?($core_ty); $($trait_name)*;);
    };

    // Implements `CoreProxy`
    (
        impl_inner: $name:ident
        $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
        ($core_ty:ty);
        CoreProxy $($trait_name:ident)*;
    ) => {
        impl$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? $crate::block_api::CoreProxy for $name$(< $( $lt ),+ >)? {
            type Core = $core_ty;
            fn compose(core: Self::Core, buffer: $crate::block_api::Buffer<Self::Core>) -> Self {
                Self { core, buffer }
            }
            fn decompose(self) -> (Self::Core, $crate::block_api::Buffer<Self::Core>) {
                let Self { ref core, ref buffer } = self;
                (core.clone(), buffer.clone())
            }
        }

        $crate::buffer_fixed!(impl_inner: $name$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?($core_ty); $($trait_name)*;);
    };

    // Implements `Update`
    (
        impl_inner: $name:ident
        $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
        ($core_ty:ty);
        Update $($trait_name:ident)*;
    ) => {
        impl$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? $crate::Update for $name$(< $( $lt ),+ >)? {
            #[inline]
            fn update(&mut self, data: &[u8]) {
                let Self { core, buffer } = self;
                buffer.digest_blocks(data, |blocks| {
                    $crate::block_api::UpdateCore::update_blocks(core, blocks)
                });
            }
        }

        $crate::buffer_fixed!(impl_inner: $name$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?($core_ty); $($trait_name)*;);
    };

    // Implements `FixedOutput`
    (
        impl_inner: $name:ident
        $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
        ($core_ty:ty);
        FixedOutput $($trait_name:ident)*;
    ) => {
        impl$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? $crate::FixedOutput for $name$(< $( $lt ),+ >)? {
            #[inline]
            fn finalize_into(mut self, out: &mut $crate::Output<Self>) {
                let Self { core, buffer } = &mut self;
                $crate::block_api::FixedOutputCore::finalize_fixed_core(core, buffer, out);
            }
        }

        $crate::buffer_fixed!(impl_inner: $name$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?($core_ty); $($trait_name)*;);
    };

    // Implements `Default`
    (
        impl_inner: $name:ident
        $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
        ($core_ty:ty);
        Default $($trait_name:ident)*;
    ) => {
        impl$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? Default for $name$(< $( $lt ),+ >)? {
            #[inline]
            fn default() -> Self {
                Self {
                    core: Default::default(),
                    buffer: Default::default(),
                }
            }
        }

        $crate::buffer_fixed!(impl_inner: $name$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?($core_ty); $($trait_name)*;);
    };

    // Implements `CustomizedInit`
    (
        impl_inner: $name:ident
        $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
        ($core_ty:ty);
        CustomizedInit $($trait_name:ident)*;
    ) => {
        impl$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? $crate::CustomizedInit for $name$(< $( $lt ),+ >)? {
            #[inline]
            fn new_customized(customization: &[u8]) -> Self {
                Self {
                    core: $crate::CustomizedInit::new_customized(customization),
                    buffer: Default::default(),
                }
            }
        }

        $crate::buffer_fixed!(impl_inner: $name$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?($core_ty); $($trait_name)*;);
    };

    // Implements `Clone`
    (
        impl_inner: $name:ident
        $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
        ($core_ty:ty);
        Clone $($trait_name:ident)*;
    ) => {
        impl$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? Clone for $name$(< $( $lt ),+ >)? {
            #[inline]
            fn clone(&self) -> Self {
                Self {
                    core: Clone::clone(&self.core),
                    buffer: Clone::clone(&self.buffer),
                }
            }
        }

        $crate::buffer_fixed!(impl_inner: $name$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?($core_ty); $($trait_name)*;);
    };

    // Implements `HashMarker` and asserts that `$core_ty` implements it
    (
        impl_inner: $name:ident
        $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
        ($core_ty:ty);
        HashMarker $($trait_name:ident)*;
    ) => {
        impl$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? $crate::HashMarker for $name$(< $( $lt ),+ >)? {}

        // Verify that `$core_ty` implements `HashMarker`
        const _: () = {
            fn check$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?(v: &$core_ty) {
                v as &dyn $crate::HashMarker;
            }
        };

        $crate::buffer_fixed!(impl_inner: $name$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?($core_ty); $($trait_name)*;);
    };

    // Implements `MacMarker` and asserts that `$core_ty` implements it
    (
        impl_inner: $name:ident
        $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
        ($core_ty:ty);
        MacMarker $($trait_name:ident)*;
    ) => {
        impl$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? $crate::MacMarker for $name$(< $( $lt ),+ >)? {}

        // Verify that `$core_ty` implements `MacMarker`
        const _: () = {
            fn check$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?(v: &$core_ty) {
                v as &dyn $crate::MacMarker;
            }
        };

        $crate::buffer_fixed!(impl_inner: $name$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?($core_ty); $($trait_name)*;);
    };

    // Implements `InnerUser` and `InnerInit`
    (
        impl_inner: $name:ident
        $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
        ($core_ty:ty);
        InnerInit $($trait_name:ident)*;
    ) => {
        impl$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? $crate::crypto_common::InnerUser for $name$(< $( $lt ),+ >)? {
            type Inner = <$core_ty as $crate::crypto_common::InnerUser>::Inner;
        }

        impl$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? $crate::crypto_common::InnerInit for $name$(< $( $lt ),+ >)? {
            #[inline]
            fn inner_init(inner: Self::Inner) -> Self {
                Self {
                    core: <$core_ty as $crate::crypto_common::InnerInit>::inner_init(inner),
                    buffer: Default::default(),
                }
            }
        }

        $crate::buffer_fixed!(impl_inner: $name$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?($core_ty); $($trait_name)*;);
    };

    // Implements `KeySizeUser` and `KeyInit`
    (
        impl_inner: $name:ident
        $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
        ($core_ty:ty);
        KeyInit $($trait_name:ident)*;
    ) => {
        impl$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? $crate::crypto_common::KeySizeUser for $name$(< $( $lt ),+ >)? {
            type KeySize = <$core_ty as $crate::crypto_common::KeySizeUser>::KeySize;
        }

        impl$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? $crate::KeyInit for $name$(< $( $lt ),+ >)? {
            #[inline]
            fn new(key: &$crate::Key<Self>) -> Self {
                Self {
                    core: <$core_ty as $crate::KeyInit>::new(key),
                    buffer: Default::default(),
                }
            }

            #[inline]
            fn new_from_slice(key: &[u8]) -> Result<Self, $crate::InvalidLength> {
                <$core_ty as $crate::KeyInit>::new_from_slice(key).map(|core|
                    Self { core, buffer: Default::default() }
                )
            }
        }

        $crate::buffer_fixed!(impl_inner: $name$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?($core_ty); $($trait_name)*;);
    };

    // Implements `Reset`
    (
        impl_inner: $name:ident
        $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
        ($core_ty:ty);
        Reset $($trait_name:ident)*;
    ) => {
        impl$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? $crate::Reset for $name$(< $( $lt ),+ >)? {
            #[inline]
            fn reset(&mut self) {
                $crate::Reset::reset(&mut self.core);
                self.buffer.reset();
            }
        }

        $crate::buffer_fixed!(impl_inner: $name$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?($core_ty); $($trait_name)*;);
    };

    // Implements `FixedOutputReset`
    (
        impl_inner: $name:ident
        $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
        ($core_ty:ty);
        FixedOutputReset $($trait_name:ident)*;
    ) => {
        impl$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? $crate::FixedOutputReset for $name$(< $( $lt ),+ >)? {
            #[inline]
            fn finalize_into_reset(&mut self, out: &mut $crate::Output<Self>) {
                let Self { core, buffer } = self;
                $crate::block_api::FixedOutputCore::finalize_fixed_core(core, buffer, out);
                $crate::Reset::reset(self);
            }
        }

        $crate::buffer_fixed!(impl_inner: $name$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?($core_ty); $($trait_name)*;);
    };

    // Implements `SerializableState`
    (
        impl_inner: $name:ident
        $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
        ($core_ty:ty);
        SerializableState $($trait_name:ident)*;
    ) => {
        impl$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? $crate::crypto_common::hazmat::SerializableState for $name$(< $( $lt ),+ >)? {
            type SerializedStateSize = $crate::typenum::Sum<
                <$core_ty as $crate::crypto_common::hazmat::SerializableState>::SerializedStateSize,
                $crate::typenum::Add1<
                    <$core_ty as $crate::block_api::BlockSizeUser>::BlockSize
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

        $crate::buffer_fixed!(impl_inner: $name$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?($core_ty); $($trait_name)*;);
    }
}
