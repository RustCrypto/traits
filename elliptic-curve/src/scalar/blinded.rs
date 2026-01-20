//! Random blinding support for [`Scalar`]

use super::Scalar;
use crate::{CurveArithmetic, ops::Invert};
use common::Generate;
use core::fmt;
use rand_core::{CryptoRng, TryCryptoRng};
use subtle::CtOption;
use zeroize::Zeroize;

#[cfg(feature = "getrandom")]
use common::getrandom::{self, SysRng};

/// Scalar blinded with a randomly generated masking value.
///
/// This provides a randomly blinded impl of [`Invert`] which is useful for
/// e.g. ECDSA ephemeral (`k`) scalars.
///
/// It implements masked variable-time inversions using Stein's algorithm, which
/// may be helpful for performance on embedded platforms.
#[derive(Clone)]
pub struct BlindedScalar<C>
where
    C: CurveArithmetic,
{
    /// Actual scalar value.
    scalar: Scalar<C>,

    /// Mask value.
    mask: Scalar<C>,
}

impl<C: CurveArithmetic> fmt::Debug for BlindedScalar<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlindedScalar").finish_non_exhaustive()
    }
}

impl<C> BlindedScalar<C>
where
    C: CurveArithmetic,
{
    /// Create a new [`BlindedScalar`] using the system's ambient secure RNG.
    #[cfg(feature = "getrandom")]
    pub fn new(scalar: Scalar<C>) -> Self {
        Self::try_new(scalar).expect("RNG error")
    }

    /// Create a new [`BlindedScalar`] using the system's ambient secure RNG.
    #[cfg(feature = "getrandom")]
    pub fn try_new(scalar: Scalar<C>) -> Result<Self, getrandom::Error> {
        Self::try_new_from_rng(scalar, &mut SysRng)
    }

    /// Create a new [`BlindedScalar`] from a scalar and a [`CryptoRng`].
    pub fn new_from_rng<R: CryptoRng + ?Sized>(scalar: Scalar<C>, rng: &mut R) -> Self {
        let Ok(ret) = Self::try_new_from_rng(scalar, rng);
        ret
    }

    /// Create a new [`BlindedScalar`] from a scalar and a [`CryptoRng`].
    pub fn try_new_from_rng<R>(scalar: Scalar<C>, rng: &mut R) -> Result<Self, R::Error>
    where
        R: TryCryptoRng + ?Sized,
    {
        let mask = Scalar::<C>::try_generate_from_rng(rng)?;
        Ok(Self { scalar, mask })
    }
}

impl<C> AsRef<Scalar<C>> for BlindedScalar<C>
where
    C: CurveArithmetic,
{
    fn as_ref(&self) -> &Scalar<C> {
        &self.scalar
    }
}

impl<C> Invert for BlindedScalar<C>
where
    C: CurveArithmetic,
{
    type Output = CtOption<Scalar<C>>;

    fn invert(&self) -> CtOption<Scalar<C>> {
        // prevent side channel analysis of scalar inversion by pre-and-post-multiplying
        // with the random masking scalar
        (self.scalar * self.mask)
            .invert_vartime()
            .map(|s| s * self.mask)
    }
}

impl<C> Drop for BlindedScalar<C>
where
    C: CurveArithmetic,
{
    fn drop(&mut self) {
        self.scalar.zeroize();
        self.mask.zeroize();
    }
}
