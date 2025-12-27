use hybrid_array::{Array, ArraySize};
use rand_core::{CryptoRng, TryCryptoRng};

#[cfg(feature = "getrandom")]
use crate::RngError;

/// Secure random generation.
pub trait Generate: Sized {
    /// Generate random key using the provided [`TryCryptoRng`].
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error>;

    /// Generate random key using the provided [`CryptoRng`].
    fn generate_from_rng<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let Ok(ret) = Self::try_generate_from_rng(rng);
        ret
    }

    /// Randomly generate a value of this type using the system's ambient cryptographically secure
    /// random number generator.
    ///
    /// # Errors
    /// Returns [`RngError`] in the event the system's ambient RNG experiences an internal failure.
    #[cfg(feature = "getrandom")]
    fn try_generate() -> Result<Self, RngError> {
        Self::try_generate_from_rng(&mut sys_rng::SysRng)
    }

    /// Randomly generate a value of this type using the system's ambient cryptographically secure
    /// random number generator.
    ///
    /// # Panics
    /// This method will panic in the event the system's ambient RNG experiences an internal
    /// failure.
    ///
    /// This shouldn't happen on most modern operating systems.
    #[cfg(feature = "getrandom")]
    fn generate() -> Self {
        Self::try_generate().expect("RNG failure")
    }
}

impl Generate for u32 {
    #[inline]
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        rng.try_next_u32()
    }
}

impl Generate for u64 {
    #[inline]
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        rng.try_next_u64()
    }
}

impl<const N: usize> Generate for [u8; N] {
    #[inline]
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        let mut ret = [0u8; N];
        rng.try_fill_bytes(&mut ret)?;
        Ok(ret)
    }
}

impl<U: ArraySize> Generate for Array<u8, U> {
    #[inline]
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        let mut ret = Self::default();
        rng.try_fill_bytes(&mut ret)?;
        Ok(ret)
    }
}

impl<U: ArraySize> Generate for Array<u32, U> {
    #[inline]
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        Self::try_from_fn(|_| rng.try_next_u32())
    }
}

impl<U: ArraySize> Generate for Array<u64, U> {
    #[inline]
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        Self::try_from_fn(|_| rng.try_next_u64())
    }
}

#[cfg(feature = "getrandom")]
pub(crate) mod sys_rng {
    use getrandom::Error;
    use rand_core::{TryCryptoRng, TryRngCore};

    /// A [`TryRngCore`] interface over the system's preferred random number source
    // TODO(tarcieri): replace this with `getrandom::SysRng` when `sys_rng` feature is available
    #[derive(Clone, Copy, Debug, Default)]
    pub struct SysRng;

    impl TryRngCore for SysRng {
        type Error = Error;

        #[inline]
        fn try_next_u32(&mut self) -> Result<u32, Error> {
            getrandom::u32()
        }

        #[inline]
        fn try_next_u64(&mut self) -> Result<u64, Error> {
            getrandom::u64()
        }

        #[inline]
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
            getrandom::fill(dest)
        }
    }

    impl TryCryptoRng for SysRng {}
}
