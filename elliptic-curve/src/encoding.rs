//! Traits for decoding/encoding elliptic curve elements (i.e. base and scalar
//! field elements) as bytes.

use generic_array::{ArrayLength, GenericArray};
use subtle::{ConditionallySelectable, CtOption};

/// Try to decode the given bytes into a curve element
pub trait FromBytes: ConditionallySelectable + Sized {
    /// Size of the serialized byte array
    type Size: ArrayLength<u8>;

    /// Try to decode this object from bytes
    fn from_bytes(bytes: &GenericArray<u8, Self::Size>) -> CtOption<Self>;
}

/// Encode this curve element as bytes
pub trait ToBytes {
    /// Size of the serialized byte array
    type Size: ArrayLength<u8>;

    /// Encode this object to bytes
    fn to_bytes(&self) -> GenericArray<u8, Self::Size>;
}
