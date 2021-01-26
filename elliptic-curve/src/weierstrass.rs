//! Elliptic curves in short Weierstrass form.

use crate::FieldBytes;
use subtle::{Choice, CtOption};

/// Marker trait for elliptic curves in short Weierstrass form.
pub trait Curve: super::Curve {}

/// Point compression settings.
pub trait PointCompression {
    /// Should point compression be applied by default?
    const COMPRESS_POINTS: bool;
}

/// Point compaction settings
pub trait PointCompaction {
    /// Should point compaction be applied by default?
    const COMPACT_POINTS: bool;
}

/// Attempt to decompress an elliptic curve point from its x-coordinate and
/// a boolean flag indicating whether or not the y-coordinate is odd.
pub trait DecompressPoint<C: Curve>: Sized {
    /// Attempt to decompress an elliptic curve point.
    fn decompress(x: &FieldBytes<C>, y_is_odd: Choice) -> CtOption<Self>;
}

/// Attempt to decompact an elliptic curve point from an x-coordinate
pub trait DecompactPoint<C: Curve>: Sized {
    /// Attempt to decompact an elliptic curve point
    fn decompact(x: &FieldBytes<C>) -> CtOption<Self>;
}
