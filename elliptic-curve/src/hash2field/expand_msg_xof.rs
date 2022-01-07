use super::ExpandMsg;
use crate::hash2field::Domain;
use digest::{ExtendableOutput, ExtendableOutputDirty, FixedOutput, Update, XofReader};
use generic_array::typenum::{IsLessOrEqual, NonZero, U256, U32, U65536};
use generic_array::ArrayLength;

/// Placeholder type for implementing expand_message_xof based on an extendable output function
pub struct ExpandMsgXof<HashT>
where
    HashT: Default + ExtendableOutput + ExtendableOutputDirty + FixedOutput + Update,
    HashT::OutputSize: IsLessOrEqual<U256>,
{
    reader: <HashT as ExtendableOutput>::Reader,
}

/// ExpandMsgXof implements expand_message_xof for the ExpandMsg trait
impl<HashT, L> ExpandMsg<L> for ExpandMsgXof<HashT>
where
    HashT: Default + ExtendableOutput + ExtendableOutputDirty + FixedOutput + Update,
    L: ArrayLength<u8>,
    // If `len_in_bytes` is bigger then 256, length of the `DST` will depend on
    // the output size of the hash, which is still not allowed to be bigger then 256:
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#section-5.4.2-5
    HashT::OutputSize: IsLessOrEqual<U256>,
    // Constraint set by `expand_message_xof`:
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#section-5.4.2-5
    L: NonZero + IsLessOrEqual<U65536>,
{
    fn expand_message(msg: &[u8], dst: &'static [u8]) -> Self {
        let domain = Domain::<U32>::xof::<HashT>(dst);
        let reader = HashT::default()
            .chain(msg)
            .chain(L::to_u16().to_be_bytes())
            .chain(domain.data())
            .chain([domain.len() as u8])
            .finalize_xof();
        Self { reader }
    }

    fn fill_bytes(&mut self, okm: &mut [u8]) {
        self.reader.read(okm);
    }
}
