/// Creates a newtype wrapper around another type and
/// delegates implementation of `digest` traits to it.
#[macro_export]
macro_rules! newtype_ct_variable_hash {
    (
        $(#[$ct_attr:meta])*
        $ct_vis:vis struct $ct_name:ident<$out_size:ident>($wrapped_ct:ty);
        // Ideally, we would use `$core_ty::OutputSize`, but unfortunately the compiler
        // does not accept such code. The likely reason is this issue:
        // https://github.com/rust-lang/rust/issues/79629
        max_size: $max_size:ty;
    ) => {
        $(#[$ct_attr])*
        $ct_vis struct $ct_name<$out_size>
        where
            $out_size: $crate::array::ArraySize + $crate::typenum::IsLessOrEqual<$max_size>,
            $crate::typenum::LeEq<$out_size, $max_size>: $crate::typenum::NonZero,
        {
            inner: $wrapped_ct,
        }

        impl<$out_size> core::fmt::Debug for $ct_name<$out_size>
        where
            $out_size: $crate::array::ArraySize + $crate::typenum::IsLessOrEqual<$max_size>,
            $crate::typenum::LeEq<$out_size, $max_size>: $crate::typenum::NonZero,
        {
            #[inline]
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($ct_name), " { ... }"))
            }
        }

        impl<$out_size> $crate::crypto_common::AlgorithmName for $ct_name<$out_size>
        where
            $out_size: $crate::array::ArraySize + $crate::typenum::IsLessOrEqual<$max_size>,
            $crate::typenum::LeEq<$out_size, $max_size>: $crate::typenum::NonZero,
        {
            #[inline]
            fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
                <$wrapped_ct as $crate::crypto_common::AlgorithmName>::write_alg_name(f)
            }
        }

        impl<$out_size> Clone for $ct_name<$out_size>
        where
            $out_size: $crate::array::ArraySize + $crate::typenum::IsLessOrEqual<$max_size>,
            $crate::typenum::LeEq<$out_size, $max_size>: $crate::typenum::NonZero,
        {
            #[inline]
            fn clone(&self) -> Self {
                let inner = <$wrapped_ct as Clone>::clone(&self.inner);
                Self { inner }
            }
        }

        impl<$out_size> Default for $ct_name<$out_size>
        where
            $out_size: $crate::array::ArraySize + $crate::typenum::IsLessOrEqual<$max_size>,
            $crate::typenum::LeEq<$out_size, $max_size>: $crate::typenum::NonZero,
        {
            #[inline]
            fn default() -> Self {
                let inner = <$wrapped_ct as Default>::default();
                Self { inner }
            }
        }

        impl<$out_size> $crate::Reset for $ct_name<$out_size>
        where
            $out_size: $crate::array::ArraySize + $crate::typenum::IsLessOrEqual<$max_size>,
            $crate::typenum::LeEq<$out_size, $max_size>: $crate::typenum::NonZero,
        {
            #[inline]
            fn reset(&mut self) {
                <$wrapped_ct as $crate::Reset>::reset(&mut self.inner);
            }
        }

        impl<$out_size> $crate::core_api::BlockSizeUser for $ct_name<$out_size>
        where
            $out_size: $crate::array::ArraySize + $crate::typenum::IsLessOrEqual<$max_size>,
            $crate::typenum::LeEq<$out_size, $max_size>: $crate::typenum::NonZero,
        {
            type BlockSize = <$wrapped_ct as $crate::crypto_common::BlockSizeUser>::BlockSize;
        }

        impl<$out_size> $crate::OutputSizeUser for $ct_name<$out_size>
        where
            $out_size: $crate::array::ArraySize + $crate::typenum::IsLessOrEqual<$max_size>,
            $crate::typenum::LeEq<$out_size, $max_size>: $crate::typenum::NonZero,
        {
            type OutputSize = <$wrapped_ct as $crate::crypto_common::OutputSizeUser>::OutputSize;
        }

        impl<$out_size> $crate::HashMarker for $ct_name<$out_size>
        where
            $out_size: $crate::array::ArraySize + $crate::typenum::IsLessOrEqual<$max_size>,
            $crate::typenum::LeEq<$out_size, $max_size>: $crate::typenum::NonZero,
        {}

        // Verify that `$wrapped_ty` implements `HashMarker`
        const _: () = {
            fn check<$out_size>(v: &$wrapped_ct)
            where
                $out_size: $crate::array::ArraySize + $crate::typenum::IsLessOrEqual<$max_size>,
                $crate::typenum::LeEq<$out_size, $max_size>: $crate::typenum::NonZero,
            {
                v as &dyn $crate::HashMarker;
            }
        };

        impl<$out_size> $crate::core_api::CoreProxy for $ct_name<$out_size>
        where
            $out_size: $crate::array::ArraySize + $crate::typenum::IsLessOrEqual<$max_size>,
            $crate::typenum::LeEq<$out_size, $max_size>: $crate::typenum::NonZero,
        {
            type Core = <$wrapped_ct as $crate::core_api::CoreProxy>::Core;
        }

        impl<$out_size> $crate::Update for $ct_name<$out_size>
        where
            $out_size: $crate::array::ArraySize + $crate::typenum::IsLessOrEqual<$max_size>,
            $crate::typenum::LeEq<$out_size, $max_size>: $crate::typenum::NonZero,
        {
            #[inline]
            fn update(&mut self, data: &[u8]) {
                <$wrapped_ct as $crate::Update>::update(&mut self.inner, data)
            }
        }

        impl<$out_size> $crate::FixedOutput for $ct_name<$out_size>
        where
            $out_size: $crate::array::ArraySize + $crate::typenum::IsLessOrEqual<$max_size>,
            $crate::typenum::LeEq<$out_size, $max_size>: $crate::typenum::NonZero,
        {
            #[inline]
            fn finalize_into(self, out: &mut $crate::Output<Self>) {
                <$wrapped_ct as $crate::FixedOutput>::finalize_into(self.inner, out)
            }
        }

        impl<$out_size> $crate::FixedOutputReset for $ct_name<$out_size>
        where
            $out_size: $crate::array::ArraySize + $crate::typenum::IsLessOrEqual<$max_size>,
            $crate::typenum::LeEq<$out_size, $max_size>: $crate::typenum::NonZero,
        {
            #[inline]
            fn finalize_into_reset(&mut self, out: &mut $crate::Output<Self>) {
                <$wrapped_ct  as $crate::FixedOutputReset>::finalize_into_reset(&mut self.inner, out);
            }
        }

        impl<$out_size> $crate::crypto_common::hazmat::SerializableState for $ct_name<$out_size>
        where
            $out_size: $crate::array::ArraySize + $crate::typenum::IsLessOrEqual<$max_size>,
            $crate::typenum::LeEq<$out_size, $max_size>: $crate::typenum::NonZero,
        {
            type SerializedStateSize = <$wrapped_ct as $crate::crypto_common::hazmat::SerializableState>::SerializedStateSize;

            #[inline]
            fn serialize(&self) -> $crate::crypto_common::hazmat::SerializedState<Self> {
                <$wrapped_ct as $crate::crypto_common::hazmat::SerializableState>::serialize(&self.inner)
            }

            #[inline]
            fn deserialize(
                serialized_state: &$crate::crypto_common::hazmat::SerializedState<Self>,
            ) -> Result<Self, $crate::crypto_common::hazmat::DeserializeStateError> {
                let inner = <$wrapped_ct as $crate::crypto_common::hazmat::SerializableState>::deserialize(serialized_state)?;
                Ok(Self { inner })
            }
        }
    };
}
