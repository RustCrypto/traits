use super::ExpandMsg;
use crate::{hash2field::Domain, Result};
use digest::{ExtendableOutput, ExtendableOutputDirty, Update, XofReader};
use generic_array::typenum::U32;

/// Placeholder type for implementing expand_message_xof based on an extendable output function
pub struct ExpandMsgXof<HashT>
where
    HashT: Default + ExtendableOutput + ExtendableOutputDirty + Update,
{
    reader: <HashT as ExtendableOutput>::Reader,
}

/// ExpandMsgXof implements expand_message_xof for the ExpandMsg trait
impl<HashT> ExpandMsg for ExpandMsgXof<HashT>
where
    HashT: Default + ExtendableOutput + ExtendableOutputDirty + Update,
{
    fn expand_message(msg: &[u8], dst: &'static [u8], len_in_bytes: usize) -> Result<Self> {
        let domain = Domain::<U32>::xof::<HashT>(dst);
        let reader = HashT::default()
            .chain(msg)
            .chain([(len_in_bytes >> 8) as u8, len_in_bytes as u8])
            .chain(domain.data())
            .chain([domain.len() as u8])
            .finalize_xof();
        Ok(Self { reader })
    }

    fn fill_bytes(&mut self, okm: &mut [u8]) {
        self.reader.read(okm);
    }
}
