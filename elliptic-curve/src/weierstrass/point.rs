//! Traits for Weierstrass elliptic curve points

use super::Curve;
use crate::FieldBytes;
use subtle::{Choice, CtOption};

/// Attempt to decompress an elliptic curve point from its x-coordinate and
/// a boolean flag indicating whether or not the y-coordinate is odd.
pub trait Decompress<C: Curve>: Sized {
    /// Attempt to decompress an elliptic curve point
    fn decompress(x: &FieldBytes<C>, y_is_odd: Choice) -> CtOption<Self>;
}
