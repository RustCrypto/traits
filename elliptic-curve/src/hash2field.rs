mod expand_msg;
mod expand_msg_xmd;
mod expand_msg_xof;

use core::ops::Mul;

pub use expand_msg::*;
pub use expand_msg_xmd::*;
pub use expand_msg_xof::*;
use generic_array::typenum::{Prod, Unsigned};
use generic_array::{ArrayLength, GenericArray};

/// The trait for helping to convert to a scalar
pub trait FromOkm {
    /// The number of bytes needed to convert to a scalar
    type Length: ArrayLength<u8>;

    /// Convert a byte sequence into a scalar
    fn from_okm(data: &GenericArray<u8, Self::Length>) -> Self;
}

/// Convert an arbitrary byte sequence according to
/// <https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-11#section-5.3>
pub fn hash_to_field<E, T, O: ArrayLength<T>>(data: &[u8], domain: &[u8]) -> GenericArray<T, O>
where
    E: ExpandMsg<Prod<T::Length, O>>,
    T: FromOkm + Default,
    T::Length: Mul<O>,
    Prod<T::Length, O>: ArrayLength<u8>,
{
    let uniform_bytes = E::expand_message(data, domain);

    uniform_bytes
        .chunks_exact(T::Length::to_usize())
        .map(GenericArray::from_slice)
        .map(T::from_okm)
        .collect()
}
