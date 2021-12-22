mod expand_msg;
mod expand_msg_xmd;
mod expand_msg_xof;

use core::convert::TryFrom;
pub use expand_msg::*;
pub use expand_msg_xmd::*;
pub use expand_msg_xof::*;

/// The trait for helping to convert to a scalar
pub trait FromOkm<const L: usize>: Sized {
    /// Convert a byte sequence into a scalar
    fn from_okm(data: &[u8; L]) -> Self;
}

/// Convert an arbitrary byte sequence according to
/// <https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-11#section-5.3>
pub fn hash_to_field<E, T, const L: usize, const COUNT: usize, const OUT: usize>(
    data: &[u8],
    domain: &[u8],
) -> [T; COUNT]
where
    E: ExpandMsg<OUT>,
    T: FromOkm<L> + Default + Copy,
{
    let random_bytes = E::expand_message(data, domain);
    let mut out = [T::default(); COUNT];
    for i in 0..COUNT {
        let u = <[u8; L]>::try_from(&random_bytes[(L * i)..L * (i + 1)]).expect("not enough bytes");
        out[i] = T::from_okm(&u);
    }
    out
}
