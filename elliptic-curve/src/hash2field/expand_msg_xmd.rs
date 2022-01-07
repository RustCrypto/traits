use super::{Domain, ExpandMsg};
use digest::{
    generic_array::{
        typenum::{IsLess, IsLessOrEqual, Unsigned, U256, U65536},
        GenericArray,
    },
    BlockInput, Digest,
};
use generic_array::ArrayLength;

/// Placeholder type for implementing expand_message_xmd based on a hash function
pub struct ExpandMsgXmd<HashT>
where
    HashT: Digest + BlockInput,
    HashT::OutputSize: IsLess<U256>,
    HashT::OutputSize: IsLessOrEqual<HashT::BlockSize>,
{
    b_0: GenericArray<u8, HashT::OutputSize>,
    b_vals: GenericArray<u8, HashT::OutputSize>,
    domain: Domain<HashT::OutputSize>,
    index: usize,
    offset: usize,
    ell: usize,
}

impl<HashT> ExpandMsgXmd<HashT>
where
    HashT: Digest + BlockInput,
    HashT::OutputSize: IsLess<U256>,
    HashT::OutputSize: IsLessOrEqual<HashT::BlockSize>,
{
    fn next(&mut self) -> bool {
        if self.index < self.ell {
            self.index += 1;
            self.offset = 0;
            // b_0 XOR b_(idx - 1)
            let mut tmp = GenericArray::<u8, HashT::OutputSize>::default();
            self.b_0
                .iter()
                .zip(&self.b_vals[..])
                .enumerate()
                .for_each(|(j, (b0val, bi1val))| tmp[j] = b0val ^ bi1val);
            self.b_vals = HashT::new()
                .chain(tmp)
                .chain([self.index as u8])
                .chain(self.domain.data())
                .chain([self.domain.len() as u8])
                .finalize();
            true
        } else {
            false
        }
    }
}

/// ExpandMsgXmd implements expand_message_xmd for the ExpandMsg trait
impl<HashT, L> ExpandMsg<L> for ExpandMsgXmd<HashT>
where
    HashT: Digest + BlockInput,
    HashT::OutputSize: IsLess<U256>,
    HashT::OutputSize: IsLessOrEqual<HashT::BlockSize>,
    L: ArrayLength<u8> + IsLess<U65536>,
{
    fn expand_message(msg: &[u8], dst: &'static [u8]) -> Self {
        let b_in_bytes = HashT::OutputSize::to_usize();
        let ell = (L::to_usize() + b_in_bytes - 1) / b_in_bytes;
        // if ell > 255 {
        //     panic!("ell was too big in expand_message_xmd");
        // }
        let domain = Domain::xmd::<HashT>(dst);
        let b_0 = HashT::new()
            .chain(GenericArray::<u8, HashT::BlockSize>::default())
            .chain(msg)
            .chain([
                L::to_u16().to_be_bytes()[0],
                L::to_u16().to_be_bytes()[1],
                0u8,
            ])
            .chain(domain.data())
            .chain([domain.len() as u8])
            .finalize();

        let b_vals = HashT::new()
            .chain(&b_0[..])
            .chain([1u8])
            .chain(domain.data())
            .chain([domain.len() as u8])
            .finalize();

        Self {
            b_0,
            b_vals,
            domain,
            index: 1,
            offset: 0,
            ell,
        }
    }

    fn fill_bytes(&mut self, okm: &mut [u8]) {
        for b in okm {
            if self.offset == self.b_vals.len() && !self.next() {
                return;
            }
            *b = self.b_vals[self.offset];
            self.offset += 1;
        }
    }
}
