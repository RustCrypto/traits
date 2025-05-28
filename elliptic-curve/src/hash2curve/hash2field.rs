//! Traits for hashing to field elements.
//!
//! <https://www.rfc-editor.org/rfc/rfc9380.html>

mod expand_msg;

use core::num::NonZeroUsize;

pub use expand_msg::{xmd::*, xof::*, *};

use crate::{Error, Result};
use hybrid_array::{
    Array, ArraySize,
    typenum::{NonZero, Unsigned},
};

/// The trait for helping to convert to a field element.
pub trait FromOkm {
    /// The number of bytes needed to convert to a field element.
    type Length: ArraySize + NonZero;

    /// Convert a byte sequence into a field element.
    fn from_okm(data: &Array<u8, Self::Length>) -> Self;
}

/// Convert an arbitrary byte sequence into a field element.
///
/// <https://www.rfc-editor.org/rfc/rfc9380.html#name-hash_to_field-implementatio>
///
/// # Errors
/// See implementors of [`ExpandMsg`] for errors:
/// - [`ExpandMsgXmd`]
/// - [`ExpandMsgXof`]
///
/// `len_in_bytes = T::Length * out.len()`
///
/// [`ExpandMsgXmd`]: crate::hash2field::ExpandMsgXmd
/// [`ExpandMsgXof`]: crate::hash2field::ExpandMsgXof
#[doc(hidden)]
pub fn hash_to_field<E, K, T>(data: &[&[u8]], domain: &[&[u8]], out: &mut [T]) -> Result<()>
where
    E: ExpandMsg<K>,
    T: FromOkm + Default,
{
    let len_in_bytes = T::Length::to_usize()
        .checked_mul(out.len())
        .and_then(NonZeroUsize::new)
        .ok_or(Error)?;
    let mut tmp = Array::<u8, <T as FromOkm>::Length>::default();
    let mut expander = E::expand_message(data, domain, len_in_bytes)?;
    for o in out.iter_mut() {
        expander.fill_bytes(&mut tmp);
        *o = T::from_okm(&tmp);
    }
    Ok(())
}
