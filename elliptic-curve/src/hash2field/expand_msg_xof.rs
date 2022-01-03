use super::ExpandMsg;
use core::marker::PhantomData;
use digest::{ExtendableOutput, Update, XofReader};

/// Placeholder type for implementing expand_message_xof based on an extendable output function
#[derive(Debug)]
pub struct ExpandMsgXof<HashT> {
    phantom: PhantomData<HashT>,
}

/// ExpandMsgXof implements expand_message_xof for the ExpandMsg trait
impl<HashT, const LEN_IN_BYTES: usize> ExpandMsg<LEN_IN_BYTES> for ExpandMsgXof<HashT>
where
    HashT: Default + ExtendableOutput + Update,
{
    fn expand_message(msg: &[u8], dst: &[u8]) -> [u8; LEN_IN_BYTES] {
        let mut buf = [0u8; LEN_IN_BYTES];
        let mut r = HashT::default()
            .chain(msg)
            .chain([(LEN_IN_BYTES >> 8) as u8, LEN_IN_BYTES as u8])
            .chain(dst)
            .chain([dst.len() as u8])
            .finalize_xof();
        r.read(&mut buf);
        buf
    }
}
