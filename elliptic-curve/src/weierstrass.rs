//! Elliptic curves in short Weierstrass form.

pub mod point;
pub mod public_key;

pub use self::{
    point::{CompressedPoint, CompressedPointSize, UncompressedPoint, UncompressedPointSize},
    public_key::{FromPublicKey, PublicKey},
};

/// Marker trait for elliptic curves in short Weierstrass form
pub trait Curve: super::Curve {}
