use super::ExpandMsg;
use crate::{hash2field::Domain, Error, Result};
use digest::{ExtendableOutput, Update, XofReader};
use generic_array::typenum::U32;

/// Placeholder type for implementing expand_message_xof based on an extendable output function
pub struct ExpandMsgXof<HashT>
where
    HashT: Default + ExtendableOutput + Update,
{
    reader: <HashT as ExtendableOutput>::Reader,
}

/// ExpandMsgXof implements expand_message_xof for the ExpandMsg trait
impl<HashT> ExpandMsg for ExpandMsgXof<HashT>
where
    HashT: Default + ExtendableOutput + Update,
{
    fn expand_message(msg: &[u8], dst: &'static [u8], len_in_bytes: usize) -> Result<Self> {
        if len_in_bytes == 0 {
            return Err(Error);
        }

        let len_in_bytes = u16::try_from(len_in_bytes).map_err(|_| Error)?;

        let domain = Domain::<U32>::xof::<HashT>(dst);
        let reader = HashT::default()
            .chain(msg)
            .chain(len_in_bytes.to_be_bytes())
            .chain(domain.data())
            .chain([domain.len()])
            .finalize_xof();
        Ok(Self { reader })
    }

    fn fill_bytes(&mut self, okm: &mut [u8]) {
        self.reader.read(okm);
    }
}
