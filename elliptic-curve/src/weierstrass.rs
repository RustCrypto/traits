//! Elliptic curves in short Weierstrass form.

pub mod point;
pub mod public_key;

pub use self::{
    point::{CompressedPoint, CompressedPointSize, UncompressedPoint, UncompressedPointSize},
    public_key::PublicKey,
};

/// Marker trait for elliptic curves in short Weierstrass form
pub trait Curve: super::Curve {
    /// Should point compression be applied by default?
    const COMPRESS_POINTS: bool;
}
