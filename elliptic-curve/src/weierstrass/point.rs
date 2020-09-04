//! Traits for Weierstrass elliptic curve points

use super::Curve;
use crate::FEBytes;
use subtle::{Choice, CtOption};

/// Attempt to decompress an elliptic curve point from its x-coordinate and
/// a boolean flag indicating whether or not the y-coordinate is odd.
pub trait Decompress<C: Curve>: Sized {
    /// Attempt to decompress an elliptic curve point
    fn decompress(x: &FEBytes<C>, y_is_odd: Choice) -> CtOption<Self>;
}
