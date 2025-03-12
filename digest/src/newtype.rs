use core::marker::PhantomData;

// https://github.com/taiki-e/pin-project/issues/102#issuecomment-540472282
#[doc(hidden)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Wrapper<'a, T> {
    pub inner: T,
    _marker: PhantomData<&'a ()>,
}

#[cfg(feature = "core-api")]
mod core_api {
    use super::Wrapper;
    use crate::core_api::BlockSizeUser;

    impl<T> BlockSizeUser for Wrapper<'_, T>
    where
        T: BlockSizeUser,
    {
        type BlockSize = <T as BlockSizeUser>::BlockSize;
    }

    #[macro_export]
    macro_rules! newtype_core_api {
        ($name: ident, $inner: ty) => {
            impl $crate::core_api::BlockSizeUser for $name
            where
                for<'a> $crate::newtype::Wrapper<'a, $inner>: $crate::core_api::BlockSizeUser,
            {
                type BlockSize = <$crate::newtype::Wrapper<'static, $inner> as $crate::core_api:: BlockSizeUser>::BlockSize;
            }
        };
    }
}

#[cfg(not(feature = "core-api"))]
#[macro_export]
macro_rules! newtype_core_api {
    ($name: ident, $inner: ty) => {};
}

mod common {
    use super::Wrapper;

    mod customized_init {
        use super::Wrapper;
        use crate::CustomizedInit;
        use core::marker::PhantomData;

        impl<T> CustomizedInit for Wrapper<'_, T>
        where
            T: CustomizedInit,
        {
            #[inline]
            fn new_customized(customization: &[u8]) -> Self {
                Wrapper {
                    inner: T::new_customized(customization),
                    _marker: PhantomData,
                }
            }
        }

        #[macro_export]
        macro_rules! newtype_common_customized_init {
            ($name: ident, $inner: ty) => {
                impl $crate::CustomizedInit for $name
                where
                    for<'a> $crate::newtype::Wrapper<'a, $inner>: $crate::CustomizedInit,
                {
                    #[inline]
                    fn new_customized(customization: &[u8]) -> Self {
                        Self($crate::newtype::Wrapper::<$inner>::new_customized(
                            customization,
                        ))
                    }
                }
            };
        }
    }

    mod extendable_output {
        use super::Wrapper;
        use crate::ExtendableOutput;

        impl<T> ExtendableOutput for Wrapper<'_, T>
        where
            T: ExtendableOutput,
        {
            type Reader = T::Reader;

            #[inline]
            fn finalize_xof(self) -> Self::Reader {
                self.inner.finalize_xof()
            }
        }

        #[macro_export]
        macro_rules! newtype_common_extendable_output {
            ($name: ident, $inner: ty) => {
                impl $crate::ExtendableOutput for $name
                where
                    for<'a> $crate::newtype::Wrapper<'a, $inner>: $crate::ExtendableOutput,
                {
                    type Reader = <$crate::newtype::Wrapper<'static, $inner> as $crate::ExtendableOutput>::Reader;

                    #[inline]
                    fn finalize_xof(self) -> Self::Reader {
                        $crate::ExtendableOutput::finalize_xof(self.0)
                    }
                }
            };
        }
    }

    mod extendable_output_reset {
        use super::Wrapper;
        use crate::ExtendableOutputReset;

        impl<T> ExtendableOutputReset for Wrapper<'_, T>
        where
            T: ExtendableOutputReset,
        {
            #[inline]
            fn finalize_xof_reset(&mut self) -> Self::Reader {
                self.inner.finalize_xof_reset()
            }
        }

        #[macro_export]
        macro_rules! newtype_common_extendable_output_reset {
            ($name: ident, $inner: ty) => {
                impl $crate::ExtendableOutputReset for $name
                where
                    for<'a> $crate::newtype::Wrapper<'a, $inner>: $crate::ExtendableOutputReset,
                {
                    #[inline]
                    fn finalize_xof_reset(&mut self) -> Self::Reader {
                        $crate::ExtendableOutputReset::finalize_xof_reset(&mut self.0)
                    }
                }
            };
        }
    }

    mod fixed_output {
        use super::Wrapper;
        use crate::{FixedOutput, Output};

        impl<T> FixedOutput for Wrapper<'_, T>
        where
            T: FixedOutput,
        {
            #[inline]
            fn finalize_into(self, out: &mut Output<Self>) {
                self.inner.finalize_into(out)
            }
        }

        #[macro_export]
        macro_rules! newtype_common_fixed_output {
            ($name: ident, $inner: ty) => {
                impl $crate::FixedOutput for $name
                where
                    for<'a> $crate::newtype::Wrapper<'a, $inner>: $crate::FixedOutput,
                {
                    #[inline]
                    fn finalize_into(self, out: &mut $crate::Output<Self>) {
                        $crate::FixedOutput::finalize_into(self.0, out)
                    }
                }
            };
        }
    }

    mod fixed_output_reset {
        use super::Wrapper;
        use crate::{FixedOutputReset, Output};

        impl<T> FixedOutputReset for Wrapper<'_, T>
        where
            T: FixedOutputReset,
        {
            #[inline]
            fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
                self.inner.finalize_into_reset(out)
            }
        }

        #[macro_export]
        macro_rules! newtype_common_fixed_output_reset {
            ($name: ident, $inner: ty) => {
                impl $crate::FixedOutputReset for $name
                where
                    for<'a> $crate::newtype::Wrapper<'a, $inner>: $crate::FixedOutputReset,
                {
                    #[inline]
                    fn finalize_into_reset(&mut self, out: &mut $crate::Output<Self>) {
                        $crate::FixedOutputReset::finalize_into_reset(&mut self.0, out)
                    }
                }
            };
        }
    }

    mod hash_marker {
        use super::Wrapper;
        use crate::HashMarker;

        impl<T> HashMarker for Wrapper<'_, T> where T: HashMarker {}

        #[macro_export]
        macro_rules! newtype_common_hash_marker {
            ($name: ident, $inner: ty) => {
                impl $crate::HashMarker for $name where
                    for<'a> $crate::newtype::Wrapper<'a, $inner>: $crate::HashMarker
                {
                }
            };
        }
    }

    mod inner_user {
        use super::Wrapper;
        use crate::crypto_common::InnerUser;

        impl<T> InnerUser for Wrapper<'_, T>
        where
            T: InnerUser,
        {
            type Inner = T::Inner;
        }

        #[macro_export]
        macro_rules! newtype_common_inner_user {
            ($name: ident, $inner: ty) => {
                impl $crate::crypto_common::InnerUser for $name
                where
                    for<'a> $crate::newtype::Wrapper<'a, $inner>: $crate::crypto_common::InnerUser,
                {
                    type Inner =
                        <$crate::newtype::Wrapper<'static, $inner> as $crate::crypto_common::InnerUser>::Inner;
                }
            };
        }
    }

    mod output_size_user {
        use super::Wrapper;
        use crate::OutputSizeUser;

        impl<T> OutputSizeUser for Wrapper<'_, T>
        where
            T: OutputSizeUser,
        {
            type OutputSize = <T as OutputSizeUser>::OutputSize;
        }

        #[macro_export]
        macro_rules! newtype_common_output_size_user {
            ($name: ident, $inner: ty) => {
                impl $crate::OutputSizeUser for $name
                where
                    for<'a> $crate::newtype::Wrapper<'a, $inner>: $crate::OutputSizeUser,
                {
                    type OutputSize =
                        <$crate::newtype::Wrapper<'static, $inner> as $crate::OutputSizeUser>::OutputSize;
                }
            };
        }
    }

    mod reset {
        use super::Wrapper;
        use crate::Reset;

        impl<T> Reset for Wrapper<'_, T>
        where
            T: Reset,
        {
            #[inline]
            fn reset(&mut self) {
                self.inner.reset()
            }
        }

        #[macro_export]
        macro_rules! newtype_common_reset {
            ($name: ident, $inner: ty) => {
                impl $crate::Reset for $name
                where
                    for<'a> $crate::newtype::Wrapper<'a, $inner>: $crate::Reset,
                {
                    #[inline]
                    fn reset(&mut self) {
                        $crate::Reset::reset(&mut self.0)
                    }
                }
            };
        }
    }

    mod update {
        use super::Wrapper;
        use crate::Update;

        impl<T> Update for Wrapper<'_, T>
        where
            T: Update,
        {
            #[inline]
            fn update(&mut self, data: &[u8]) {
                self.inner.update(data)
            }
        }

        #[macro_export]
        macro_rules! newtype_common_update {
            ($name: ident, $inner: ty) => {
                impl $crate::Update for $name
                where
                    for<'a> $crate::newtype::Wrapper<'a, $inner>: $crate::Update,
                {
                    #[inline]
                    fn update(&mut self, data: &[u8]) {
                        $crate::Update::update(&mut self.0, data)
                    }
                }
            };
        }
    }

    mod serializable_state {
        use super::Wrapper;
        use crate::crypto_common::hazmat::{
            DeserializeStateError, SerializableState, SerializedState,
        };
        use core::marker::PhantomData;

        impl<T> SerializableState for Wrapper<'_, T>
        where
            T: SerializableState,
        {
            type SerializedStateSize = <T as SerializableState>::SerializedStateSize;

            #[inline]
            fn serialize(&self) -> SerializedState<Self> {
                self.inner.serialize()
            }

            #[inline]
            fn deserialize(
                serialized_state: &SerializedState<Self>,
            ) -> Result<Self, DeserializeStateError> {
                Ok(Wrapper {
                    inner: T::deserialize(serialized_state)?,
                    _marker: PhantomData,
                })
            }
        }

        #[macro_export]
        macro_rules! newtype_common_serializable_state {
            ($name: ident, $inner: ty) => {
                impl $crate::crypto_common::hazmat::SerializableState for $name
                where
                    for<'a> $crate::newtype::Wrapper<'a, $inner>:
                        $crate::crypto_common::hazmat::SerializableState,
                {
                    type SerializedStateSize = <$crate::newtype::Wrapper<
                        'static,
                        $inner,
                    > as $crate::crypto_common::hazmat::SerializableState>::SerializedStateSize;

                    #[inline]
                    fn serialize(&self) -> $crate::crypto_common::hazmat::SerializedState<Self> {
                        self.0.serialize()
                    }

                    #[inline]
                    fn deserialize(
                        serialized_state: &$crate::crypto_common::hazmat::SerializedState<Self>,
                    ) -> Result<Self, $crate::crypto_common::hazmat::DeserializeStateError> {
                        Ok(Self($crate::newtype::Wrapper::deserialize(
                            serialized_state,
                        )?))
                    }
                }
            };
        }
    }

    #[macro_export]
    macro_rules! newtype_common {
        ($name: ident, $inner: ty) => {
            $crate::newtype_common_customized_init!($name, $inner);
            $crate::newtype_common_extendable_output!($name, $inner);
            $crate::newtype_common_extendable_output_reset!($name, $inner);
            $crate::newtype_common_fixed_output!($name, $inner);
            $crate::newtype_common_fixed_output_reset!($name, $inner);
            $crate::newtype_common_hash_marker!($name, $inner);
            $crate::newtype_common_inner_user!($name, $inner);
            $crate::newtype_common_output_size_user!($name, $inner);
            $crate::newtype_common_reset!($name, $inner);
            $crate::newtype_common_update!($name, $inner);
            $crate::newtype_common_serializable_state!($name, $inner);
        };
    }
}

#[cfg(feature = "mac")]
mod mac {
    use super::Wrapper;
    use crate::{InnerInit, MacMarker};
    use core::marker::PhantomData;

    impl<T> InnerInit for Wrapper<'_, T>
    where
        T: InnerInit,
    {
        fn inner_init(inner: Self::Inner) -> Self {
            Wrapper {
                inner: T::inner_init(inner),
                _marker: PhantomData,
            }
        }
    }

    impl<T> MacMarker for Wrapper<'_, T> where T: MacMarker {}

    #[macro_export]
    macro_rules! newtype_mac {
        ($name: ident, $inner: ty) => {
            impl $crate::InnerInit for $name
            where
                for<'a> $crate::newtype::Wrapper<'a, $inner>: $crate::InnerInit,
            {
                #[inline]
                fn inner_init(inner: Self::Inner) -> Self {
                    Self($crate::newtype::Wrapper::<'static, $inner>::inner_init(
                        inner,
                    ))
                }
            }
        };
    }
}

#[cfg(not(feature = "mac"))]
#[macro_export]
macro_rules! newtype_mac {
    ($name: ident, $inner: ty) => {};
}

#[cfg(feature = "oid")]
mod oid {
    use super::Wrapper;
    use crate::const_oid::{AssociatedOid, ObjectIdentifier};

    impl<T> AssociatedOid for Wrapper<'_, T>
    where
        T: AssociatedOid,
    {
        const OID: ObjectIdentifier = T::OID;
    }

    #[macro_export]
    macro_rules! newtype_oid {
        ($name: ident, $inner: ty) => {
            impl $crate::const_oid::AssociatedOid for $name
            where
                for<'a> $crate::newtype::Wrapper<'a, $inner>: $crate::const_oid::AssociatedOid,
            {
                const OID: $crate::const_oid::ObjectIdentifier =
                    $crate::newtype::Wrapper::<'static, $inner>::OID;
            }
        };
    }
}

#[cfg(not(feature = "oid"))]
#[macro_export]
macro_rules! newtype_oid {
    ($name: ident, $inner: ty) => {};
}

#[macro_export]
macro_rules! newtype {
    ($(#[$attr:meta])* $vis: vis struct $name: ident = $inner: ty;) => {
        $(#[$attr])*
        pub struct $name($crate::newtype::Wrapper<'static, $inner>);

        $crate::newtype_common!($name, $inner);
        $crate::newtype_oid!($name, $inner);
        $crate::newtype_core_api!($name, $inner);

        impl Clone for $name
        where
            for<'a> $crate::newtype::Wrapper<'a, $inner>: Clone,
        {
            #[inline]
            fn clone(&self) -> Self {
                Self(self.0.clone())
            }
        }

        impl Copy for $name where for<'a> $crate::newtype::Wrapper<'a, $inner>: Copy {}

        impl Default for $name
        where
            for<'a> $crate::newtype::Wrapper<'a, $inner>: Default,
        {
            #[inline]
            fn default() -> Self {
                Self($crate::newtype::Wrapper::default())
            }
        }

        impl core::fmt::Debug for $name
        where
            for<'a> $crate::newtype::Wrapper<'a, $inner>: core::fmt::Debug,
        {
            #[inline]
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}
