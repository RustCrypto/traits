use digest::{Digest, ExtendableOutputDirty, Update, XofReader};
use generic_array::typenum::{IsLessOrEqual, U256};
use generic_array::{ArrayLength, GenericArray};

/// Salt when the DST is too long
const OVERSIZE_DST_SALT: &[u8] = b"H2C-OVERSIZE-DST-";
/// Maximum domain separation tag length
const MAX_DST_LEN: usize = 255;

/// Trait for types implementing expand_message interface for hash_to_field
pub trait ExpandMsg<L: ArrayLength<u8>> {
    /// Expands `msg` to the required number of bytes in `L`
    fn expand_message(msg: &[u8], dst: &[u8]) -> GenericArray<u8, L>;
}

/// The domain separation tag
///
/// Implements [section 5.4.3 of `draft-irtf-cfrg-hash-to-curve-13`][dst].
///
/// [dst]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-13#section-5.4.3
pub(crate) enum Domain<'a, L>
where
    L: ArrayLength<u8> + IsLessOrEqual<U256>,
{
    /// > 255
    Hashed(GenericArray<u8, L>),
    /// <= 255
    Array(&'a [u8]),
}

impl<'a, L> Domain<'a, L>
where
    L: ArrayLength<u8> + IsLessOrEqual<U256>,
{
    pub fn xof<X>(dst: &'a [u8]) -> Self
    where
        X: Default + ExtendableOutputDirty + Update,
    {
        if dst.len() > MAX_DST_LEN {
            let mut data = GenericArray::<u8, L>::default();
            X::default()
                .chain(OVERSIZE_DST_SALT)
                .chain(dst)
                .finalize_xof_dirty()
                .read(&mut data);
            Self::Hashed(data)
        } else {
            Self::Array(dst)
        }
    }

    pub fn xmd<X>(dst: &'a [u8]) -> Self
    where
        X: Digest<OutputSize = L>,
    {
        if dst.len() > MAX_DST_LEN {
            Self::Hashed(X::new().chain(OVERSIZE_DST_SALT).chain(dst).finalize())
        } else {
            Self::Array(dst)
        }
    }

    pub fn data(&self) -> &[u8] {
        match self {
            Self::Hashed(d) => &d[..],
            Self::Array(d) => *d,
        }
    }

    pub fn len(&self) -> u8 {
        match self {
            Self::Hashed(_) => L::to_u8(),
            // Can't overflow because enforced on a type level.
            Self::Array(d) => d.len() as u8,
        }
    }
}
