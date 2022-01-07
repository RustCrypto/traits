use core::marker::PhantomData;

use super::ExpandMsg;
use crate::hash2field::Domain;
use digest::{ExtendableOutput, Update, XofReader};
use generic_array::typenum::{IsLessOrEqual, NonZero, U32, U65536};
use generic_array::{ArrayLength, GenericArray};

/// Placeholder type for implementing expand_message_xof based on an extendable output function
pub struct ExpandMsgXof<HashT>(PhantomData<HashT>)
where
    HashT: Default + ExtendableOutput + Update;

/// ExpandMsgXof implements expand_message_xof for the ExpandMsg trait
impl<HashT, L> ExpandMsg<L> for ExpandMsgXof<HashT>
where
    HashT: Default + ExtendableOutput + Update,
    L: ArrayLength<u8>,
    // Constraint set by `expand_message_xof`:
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#section-5.4.2-5
    L: NonZero + IsLessOrEqual<U65536>,
{
    fn expand_message(msg: &[u8], dst: &[u8]) -> GenericArray<u8, L> {
        let domain = Domain::<U32>::xof::<HashT>(dst);
        let mut reader = HashT::default()
            .chain(msg)
            .chain(L::to_u16().to_be_bytes())
            .chain(domain.data())
            .chain([domain.len()])
            .finalize_xof();
        let mut buf = GenericArray::default();
        reader.read(&mut buf);
        buf
    }
}
