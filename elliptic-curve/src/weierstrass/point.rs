//! Traits for Weierstrass elliptic curve points

use super::Curve;
use crate::ElementBytes;
use subtle::CtOption;

/// Attempt to decompress an elliptic curve point from its x-coordinate and
/// a boolean flag indicating whether or not the y-coordinate is odd.
pub trait Decompress<C: Curve>: Sized {
    /// Attempt to decompress an elliptic curve point
    fn decompress(x: &ElementBytes<C>, y_is_odd: bool) -> CtOption<Self>;
}
