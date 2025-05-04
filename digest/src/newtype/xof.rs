/// Creates a newtype wrapper around another type and
/// delegates implementation of `digest` traits to it.
#[macro_export]
macro_rules! newtype_xof_hash {
    (
        $(#[$attr:meta])*
        $v:vis struct $name:ident($wrapped_ty:ty);
        $(#[$reader_attr:meta])*
        $reader_v:vis struct $reader_name:ident($wrapped_reader_ty:ty);
        $(oid: $oid:literal)?
    ) => {
        $(#[$attr])*
        $v struct $name {
            inner: $wrapped_ty
        }

        impl core::fmt::Debug for $name {
            #[inline]
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }

        impl $crate::crypto_common::AlgorithmName for $name {
            #[inline]
            fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
                <$wrapped_ty as $crate::crypto_common::AlgorithmName>::write_alg_name(f)
            }
        }

        impl Clone for $name {
            #[inline]
            fn clone(&self) -> Self {
                Self {
                    inner: <$wrapped_ty as Clone>::clone(&self.inner),
                }
            }
        }

        impl Default for $name {
            #[inline]
            fn default() -> Self {
                Self {
                    inner: <$wrapped_ty as Default>::default(),
                }
            }
        }

        impl $crate::Reset for $name {
            #[inline]
            fn reset(&mut self) {
                $crate::Reset::reset(&mut self.inner);
            }
        }

        impl $crate::core_api::BlockSizeUser for $name {
            type BlockSize = <$wrapped_ty as $crate::crypto_common::BlockSizeUser>::BlockSize;
        }

        impl $crate::HashMarker for $name {}

        impl $crate::core_api::CoreProxy for $name {
            type Core = <$wrapped_ty as $crate::core_api::CoreProxy>::Core;
        }

        impl $crate::Update for $name {
            #[inline]
            fn update(&mut self, data: &[u8]) {
                <$wrapped_ty as $crate::Update>::update(&mut self.inner, data)
            }
        }

        impl $crate::ExtendableOutput for $name {
            type Reader = $reader_name;

            #[inline]
            fn finalize_xof(self) -> Self::Reader {
                let inner: $wrapped_reader_ty = <$wrapped_ty as $crate::ExtendableOutput>::finalize_xof(self.inner);
                $reader_name { inner }
            }
        }

        impl $crate::ExtendableOutputReset for $name {
            #[inline]
            fn finalize_xof_reset(&mut self) -> Self::Reader {
                let inner = <$wrapped_ty as $crate::ExtendableOutputReset>::finalize_xof_reset(&mut self.inner);
                $reader_name { inner }
            }
        }

        impl $crate::crypto_common::hazmat::SerializableState for $name {
            type SerializedStateSize = <$wrapped_ty as $crate::crypto_common::hazmat::SerializableState>::SerializedStateSize;

            #[inline]
            fn serialize(&self) -> $crate::crypto_common::hazmat::SerializedState<Self> {
                $crate::crypto_common::hazmat::SerializableState::serialize(&self.inner)
            }

            #[inline]
            fn deserialize(
                serialized_state: &$crate::crypto_common::hazmat::SerializedState<Self>,
            ) -> Result<Self, $crate::crypto_common::hazmat::DeserializeStateError> {
                let inner = $crate::crypto_common::hazmat::SerializableState::deserialize(serialized_state)?;
                Ok(Self { inner })
            }
        }

        $(
            #[cfg(feature = "oid")]
            impl $crate::const_oid::AssociatedOid for $name {
                const OID: $crate::const_oid::ObjectIdentifier =
                    $crate::const_oid::ObjectIdentifier::new_unwrap($oid);
            }
        )?

        $(#[$reader_attr])*
        $reader_v struct $reader_name {
            inner: $wrapped_reader_ty
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
                    inner: Clone::clone(&self.inner),
                }
            }
        }

        impl $crate::XofReader for $reader_name {
            #[inline]
            fn read(&mut self, buf: &mut [u8]) {
                $crate::XofReader::read(&mut self.inner, buf)
            }
        }
    };
}
