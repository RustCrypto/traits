//! Traits for elliptic curve points

/// Obtain the generator point.
pub trait Generator {
    /// Get the generator point for this elliptic curve
    fn generator() -> Self;
}
