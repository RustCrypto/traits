/// Creates a newtype wrapper around another type and
/// delegates implementation of `digest` traits to it.
#[macro_export]
macro_rules! newtype {
    (
        $(#[$attr:meta])*
        $v:vis struct $name:ident($wrapped_ty:ty);
        $(delegate_template: $template_name:ident)?
        $(delegate: $($trait_name:ident)*)?
        $(oid: $oid:literal)?
    ) => {
        $(#[$attr])*
        $v struct $name($wrapped_ty);

        $(
            $crate::newtype!(template_impl: $template_name $name($wrapped_ty));
        )?

        $(
            $crate::newtype!(delegate_impls: $name($wrapped_ty) $($trait_name)*);
        )?

        $(
            #[cfg(feature = "oid")]
            impl $crate::const_oid::AssociatedOid for $name {
                const OID: $crate::const_oid::ObjectIdentifier =
                    $crate::const_oid::ObjectIdentifier::new_unwrap($oid);
            }
        )?
    };

    (template_impl: FixedOutputHash $name:ident($wrapped_ty:ty)) => {
        $crate::newtype!(
            delegate_impls: $name($wrapped_ty)
            Debug Clone Default
            AlgorithmName SerializableState
            BlockSizeUser OutputSizeUser
            HashMarker Reset Update
            FixedOutput FixedOutputReset
        );
    };

    (delegate_impls: $name:ident($wrapped_ty:ty) $($trait_name:ident)*) => {
        $(
            $crate::newtype!(delegate_impl: $name($wrapped_ty) $trait_name);
        )*
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) Debug) => {
        impl core::fmt::Debug for $name {
            #[inline]
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) AlgorithmName) => {
        impl $crate::crypto_common::AlgorithmName for $name {
            #[inline]
            fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
                <$wrapped_ty as $crate::crypto_common::AlgorithmName>::write_alg_name(f)
            }
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) Clone) => {
        impl Clone for $name {
            #[inline]
            fn clone(&self) -> Self {
                Self(<$wrapped_ty as Clone>::clone(&self.0))
            }
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) Default) => {
        impl Default for $name {
            #[inline]
            fn default() -> Self {
                Self(<$wrapped_ty as Default>::default())
            }
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) InnerInit) => {
        impl $crate::InnerInit for $name {
            #[inline]
            fn new(inner: Self::Inner) -> Self {
                Self(<$wrapped_ty as $crate::InnerInit>::new(inner))
            }
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) KeyInit) => {
        impl $crate::KeyInit for $name {
            #[inline]
            fn new(key: &$crate::Key<Self>) -> Self {
                Self(<$wrapped_ty as $crate::KeyInit>::new(key))
            }
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) CustomizedInit) => {
        impl $crate::CustomizedInit for $name {
            #[inline]
            fn new_customized(customization: &[u8]) -> Self {
                <$wrapped_ty as $crate::CustomizedInit>::new_customized(customization)
            }
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) Reset) => {
        impl $crate::Reset for $name {
            #[inline]
            fn reset(&mut self) {
                <$wrapped_ty as $crate::Reset>::reset(&mut self.0);
            }
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) BlockSizeUser) => {
        impl $crate::core_api::BlockSizeUser for $name {
            type BlockSize = <$wrapped_ty as $crate::crypto_common::BlockSizeUser>::BlockSize;
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) OutputSizeUser) => {
        impl $crate::OutputSizeUser for $name {
            type OutputSize = <$wrapped_ty as $crate::core_api::OutputSizeUser>::OutputSize;
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) KeySizeUser) => {
        impl $crate::crypto_common::KeySizeUser for $name {
            type KeySize = <$wrapped_ty as $crate::crypto_common::KeySizeUser>::KeySize;
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) HashMarker) => {
        impl $crate::HashMarker for $name {}

        // TODO: assert that `$wrapped_ty` impls `HashMarker`?
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) MacMarker) => {
        impl $crate::MacMarker for $name {}

        // TODO: assert that `$wrapped_ty` impls `MacMarker`?
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) Update) => {
        impl $crate::Update for $name {
            #[inline]
            fn update(&mut self, data: &[u8]) {
                <$wrapped_ty as $crate::Update>::update(&mut self.0, data)
            }
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) CoreProxy) => {
        impl $crate::core_api::CoreProxy for $name {
            type Core = <$wrapped_ty as $crate::core_api::CoreProxy>::Core;
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) FixedOutput) => {
        impl $crate::FixedOutput for $name {
            #[inline]
            fn finalize_into(self, out: &mut $crate::Output<Self>) {
                <$wrapped_ty as $crate::FixedOutput>::finalize_into(self.0, out)
            }
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) FixedOutputReset) => {
        impl $crate::FixedOutputReset for $name {
            #[inline]
            fn finalize_into_reset(&mut self, out: &mut $crate::Output<Self>) {
                <$wrapped_ty as $crate::FixedOutputReset>::finalize_into_reset(&mut self.0, out);
            }
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) VariableOutput) => {
        impl $crate::VariableOutput for $name {
            const MAX_OUTPUT_SIZE: usize = <$wrapped_ty as $crate::VariableOutput>::MAX_OUTPUT_SIZE;

            #[inline]
            fn new(output_size: usize) -> Result<Self, $crate::InvalidOutputSize> {
                <$wrapped_ty as $crate::VariableOutput>::new(output_size)
            }

            #[inline]
            fn output_size(&self) -> usize {
                <$wrapped_ty as $crate::VariableOutput>::output_size(&self.0)
            }

            #[inline]
            fn finalize_variable(self, out: &mut [u8]) -> Result<(), $crate::InvalidBufferSize> {
                <$wrapped_ty as $crate::VariableOutput>::finalize_variable(self.0, out)
            }
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) VariableOutputReset) => {
        impl $crate::VariableOutputReset for $name {
            #[inline]
            fn finalize_variable_reset(
                &mut self,
                out: &mut [u8],
            ) -> Result<(), $crate::InvalidBufferSize> {
                <$wrapped_ty as $crate::VariableOutputReset>::finalize_variable_reset(&mut self.0, out)
            }
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) ExtendableOutput) => {
        impl $crate::ExtendableOutput for $name {
            // TODO: use a newtype wrapper?
            type Reader = <$wrapped_ty as $crate::ExtendableOutput>::Reader;

            #[inline]
            fn finalize_xof(self) -> Self::Reader {
                <$wrapped_ty as $crate::ExtendanbleOutput>::finalize_xof(self.0)
            }
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) ExtendableOutputReset) => {
        impl $crate::ExtendableOutputReset for $name {
            #[inline]
            fn finalize_xof_reset(&mut self) -> Self::Reader {
                <$wrapped_ty as $crate::ExtendableOutputReset>::finalize_xof_reset(&mut self.0)
            }
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) SerializableState) => {
        impl $crate::crypto_common::hazmat::SerializableState for $name {
            type SerializedStateSize = <$wrapped_ty as $crate::crypto_common::hazmat::SerializableState>::SerializedStateSize;

            #[inline]
            fn serialize(&self) -> $crate::crypto_common::hazmat::SerializedState<Self> {
                <$wrapped_ty as $crate::crypto_common::hazmat::SerializableState>::serialize(&self.0)
            }

            #[inline]
            fn deserialize(
                serialized_state: &$crate::crypto_common::hazmat::SerializedState<Self>,
            ) -> Result<Self, $crate::crypto_common::hazmat::DeserializeStateError> {
                <$wrapped_ty as $crate::crypto_common::hazmat::SerializableState>::deserialize(serialized_state).map(Self)
            }
        }
    };
}
