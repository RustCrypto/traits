use super::ExpandMsg;
use crate::hash2field::Domain;
use digest::{ExtendableOutput, ExtendableOutputDirty, Update, XofReader};
use generic_array::{typenum::U32, ArrayLength};

/// Placeholder type for implementing expand_message_xof based on an extendable output function
pub struct ExpandMsgXof<HashT>
where
    HashT: Default + ExtendableOutput + ExtendableOutputDirty + Update,
{
    reader: <HashT as ExtendableOutput>::Reader,
}

/// ExpandMsgXof implements expand_message_xof for the ExpandMsg trait
impl<HashT, L> ExpandMsg<L> for ExpandMsgXof<HashT>
where
    HashT: Default + ExtendableOutput + ExtendableOutputDirty + Update,
    L: ArrayLength<u8>,
{
    fn expand_message(msg: &[u8], dst: &'static [u8]) -> Self {
        let domain = Domain::<U32>::xof::<HashT>(dst);
        let reader = HashT::default()
            .chain(msg)
            .chain([(L::to_usize() >> 8) as u8, L::to_usize() as u8])
            .chain(domain.data())
            .chain([domain.len() as u8])
            .finalize_xof();
        Self { reader }
    }

    fn fill_bytes(&mut self, okm: &mut [u8]) {
        self.reader.read(okm);
    }
}
