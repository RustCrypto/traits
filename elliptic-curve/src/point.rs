//! Traits for elliptic curve points

/// Point compression settings
pub trait Compression {
    /// Should point compression be applied by default?
    const COMPRESS_POINTS: bool;
}

/// Obtain the generator point.
pub trait Generator {
    /// Get the generator point for this elliptic curve
    fn generator() -> Self;
}
