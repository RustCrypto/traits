//! Field elements.

use crate::Curve;
use generic_array::GenericArray;

/// Size of serialized field elements of this elliptic curve.
pub type FieldBytesSize<C> = <C as Curve>::FieldBytesSize;

/// Byte representation of a base/scalar field element of a given curve.
pub type FieldBytes<C> = GenericArray<u8, FieldBytesSize<C>>;
