//! Elliptic curves in short Weierstrass form.

pub mod point;

/// Marker trait for elliptic curves in short Weierstrass form
pub trait Curve: super::Curve {
    /// Should point compression be applied by default?
    const COMPRESS_POINTS: bool;
}
