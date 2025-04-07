/// Creates a newtype wrapper around another type and
/// delegates implementation of `digest` traits to it.
#[macro_export]
macro_rules! newtype {
    (
        $(#[$attr:meta])*
        $name:ident($wrapped_ty:ty);
        delegate: $($trait_name:ident)*
    ) => {
        $(#[$attr])*
        pub struct $name($wrapped_ty);

        $(
            $crate::newtype!(delegate_impl: $name($wrapped_ty) $trait_name);
        )*

        // Clone, Default, BlockSizeUser, CoreProxy, ExtendableOutput, FixedOutput, KeyInit,
        // OutputSizeUser, Update, HashMarker, MacMarker

        // Write
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) Debug) => {
        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) AlgorithmName) => {
        impl $crate::crypto_common::AlgorithmName for $name {
            fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
                f.write_str(stringify!($name))
            }
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) Clone) => {
        impl Clone for $name {
            #[inline]
            fn clone(&self) -> Self {
                Self(self.0.clone())
            }
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) Default) => {
        impl Default for $name {
            #[inline]
            fn default() -> Self {
                Self(Default::default())
            }
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) InnerInit) => {
        impl $crate::InnerInit for $name {
            #[inline]
            fn new(inner: Self::Inner) -> Self {
                self.0.new(inner)
            }
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) KeyInit) => {
        impl $crate::KeyInit for $name {
            #[inline]
            fn new(key: &$crate::Key<Self>) -> Self {
                self.0.new(key)
            }
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) CustomizedInit) => {
        impl $crate::CustomizedInit for $name {
            #[inline]
            fn new_customized(customization: &[u8]) -> Self {
                $wrapped_ty::new_customized(customization)
            }
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) Reset) => {
        impl Reset for $name {
            #[inline]
            fn reset(&mut self) {
                self.0.reset()
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
                self.0.update(data)
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
                self.0.finalize_into(out);
            }
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) FixedOutputReset) => {
        impl $crate::FixedOutputReset for $name {
            #[inline]
            fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
                self.0.finalize_into_reset(out);
            }
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) VariableOutput) => {
        impl $crate::VariableOutput for $name {
            const MAX_OUTPUT_SIZE: usize = <$wrapped_ty as $crate::VariableOutput>::MAX_OUTPUT_SIZE;

            #[inline]
            fn new(output_size: usize) -> Result<Self, $crate::InvalidOutputSize> {
                $wrapped_ty::new(output_size)
            }

            #[inline]
            fn output_size(&self) -> usize {
                self.0.output_size()
            }

            #[inline]
            fn finalize_variable(self, out: &mut [u8]) -> Result<(), $crate::InvalidBufferSize> {
                self.0.finalize_variable(out)
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
                self.0.finalize_variable_reset(out)
            }
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) ExtendableOutput) => {
        impl $crate::ExtendableOutput for $name {
            // TODO: use a newtype wrapper?
            type Reader = <$wrapped_ty as $crate::ExtendableOutput>::Reader;

            fn finalize_xof(self) -> Self::Reader {
                self.0.finalize_xof()
            }
        }
    };

    (delegate_impl: $name:ident($wrapped_ty:ty) ExtendableOutputReset) => {
        impl $crate::ExtendableOutputReset for $name {
            fn finalize_xof_reset(&mut self) -> Self::Reader {
                self.0.finalize_xof_reset()
            }
        }
    };
}
