/// Creates a newtype wrapper around another type and
/// delegates implementation of `digest` traits to it.
#[macro_export]
macro_rules! newtype_fixed_hash {
    (
        $(#[$attr:meta])*
        $v:vis struct $name:ident$(<$gp:ident: $bound:ident>)?($wrapped_ty:ty);
    ) => {
        $(#[$attr])*
        $v struct $name$(<$gp: $bound>)? {
            inner: $wrapped_ty
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
                <$wrapped_ty as $crate::crypto_common::AlgorithmName>::write_alg_name(f)
            }
        }

        impl$(<$gp: $bound>)? Clone for $name$(<$gp>)? {
            #[inline]
            fn clone(&self) -> Self {
                Self {
                    inner: <$wrapped_ty as Clone>::clone(&self.inner),
                }
            }
        }

        impl$(<$gp: $bound>)? Default for $name$(<$gp>)? {
            #[inline]
            fn default() -> Self {
                Self {
                    inner: <$wrapped_ty as Default>::default(),
                }
            }
        }

        impl$(<$gp: $bound>)? $crate::Reset for $name$(<$gp>)? {
            #[inline]
            fn reset(&mut self) {
                <$wrapped_ty as $crate::Reset>::reset(&mut self.inner);
            }
        }

        impl$(<$gp: $bound>)? $crate::core_api::BlockSizeUser for $name$(<$gp>)? {
            type BlockSize = <$wrapped_ty as $crate::crypto_common::BlockSizeUser>::BlockSize;
        }

        impl$(<$gp: $bound>)? $crate::OutputSizeUser for $name$(<$gp>)? {
            type OutputSize = <$wrapped_ty as $crate::core_api::OutputSizeUser>::OutputSize;
        }

        impl$(<$gp: $bound>)? $crate::HashMarker for $name$(<$gp>)? {}

        impl$(<$gp: $bound>)? $crate::core_api::CoreProxy for $name$(<$gp>)? {
            type Core = <$wrapped_ty as $crate::core_api::CoreProxy>::Core;
        }

        impl$(<$gp: $bound>)? $crate::Update for $name$(<$gp>)? {
            #[inline]
            fn update(&mut self, data: &[u8]) {
                <$wrapped_ty as $crate::Update>::update(&mut self.inner, data)
            }
        }

        impl$(<$gp: $bound>)? $crate::FixedOutput for $name$(<$gp>)? {
            #[inline]
            fn finalize_into(self, out: &mut $crate::Output<Self>) {
                <$wrapped_ty as $crate::FixedOutput>::finalize_into(self.inner, out)
            }
        }

        impl$(<$gp: $bound>)? $crate::FixedOutputReset for $name$(<$gp>)? {
            #[inline]
            fn finalize_into_reset(&mut self, out: &mut $crate::Output<Self>) {
                <$wrapped_ty as $crate::FixedOutputReset>::finalize_into_reset(&mut self.inner, out);
            }
        }

        impl$(<$gp: $bound>)? $crate::crypto_common::hazmat::SerializableState for $name$(<$gp>)? {
            type SerializedStateSize = <$wrapped_ty as $crate::crypto_common::hazmat::SerializableState>::SerializedStateSize;

            #[inline]
            fn serialize(&self) -> $crate::crypto_common::hazmat::SerializedState<Self> {
                <$wrapped_ty as $crate::crypto_common::hazmat::SerializableState>::serialize(&self.inner)
            }

            #[inline]
            fn deserialize(
                serialized_state: &$crate::crypto_common::hazmat::SerializedState<Self>,
            ) -> Result<Self, $crate::crypto_common::hazmat::DeserializeStateError> {
                let inner = <$wrapped_ty as $crate::crypto_common::hazmat::SerializableState>::deserialize(serialized_state)?;
                Ok(Self { inner })
            }
        }
    };

    (
        $(#[$attr:meta])*
        $v:vis struct $name:ident$(<$gp:ident: $bound:ident>)?($wrapped_ty:ty);
        oid: $oid:literal
    ) => {
        $crate::newtype_fixed_hash!(
            $(#[$attr])*
            $v struct $name$(<$gp: $bound>)?($wrapped_ty);
        );

        #[cfg(feature = "oid")]
        impl$(<$gp: $bound>)? $crate::const_oid::AssociatedOid for $name$(<$gp>)? {
            const OID: $crate::const_oid::ObjectIdentifier =
                $crate::const_oid::ObjectIdentifier::new_unwrap($oid);
        }
    };
}
