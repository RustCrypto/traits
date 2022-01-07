use core::ops::Mul;

use super::{Domain, ExpandMsg};
use digest::{BlockInput, Digest};
use generic_array::typenum::{IsLess, IsLessOrEqual, NonZero, Prod, Unsigned, U255, U256, U65536};
use generic_array::{ArrayLength, GenericArray};

/// Placeholder type for implementing expand_message_xmd based on a hash function
pub struct ExpandMsgXmd<HashT>
where
    HashT: Digest + BlockInput,
    HashT::OutputSize: IsLessOrEqual<U256>,
    HashT::OutputSize: IsLessOrEqual<HashT::BlockSize>,
{
    b_0: GenericArray<u8, HashT::OutputSize>,
    b_vals: GenericArray<u8, HashT::OutputSize>,
    domain: Domain<HashT::OutputSize>,
    index: u8,
    offset: usize,
    ell: u8,
}

impl<HashT> ExpandMsgXmd<HashT>
where
    HashT: Digest + BlockInput,
    HashT::OutputSize: IsLessOrEqual<U256>,
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
                .chain([self.index])
                .chain(self.domain.data())
                .chain([self.domain.len()])
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
    L: ArrayLength<u8>,
    U255: Mul<HashT::OutputSize>,
    // If `len_in_bytes` is bigger then 256, length of the `DST` will depend on
    // the output size of the hash, which is still not allowed to be bigger then 256:
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#section-5.4.1-6
    HashT::OutputSize: IsLessOrEqual<U256>,
    // Constraint set by `expand_message_xmd`:
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#section-5.4.1-4
    HashT::OutputSize: IsLessOrEqual<HashT::BlockSize>,
    // Constraint set by `expand_message_xmd`:
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#section-5.4.1-6
    L: NonZero + IsLess<Prod<U255, HashT::OutputSize>> + IsLess<U65536>,
{
    fn expand_message(msg: &[u8], dst: &'static [u8]) -> Self {
        let b_in_bytes = HashT::OutputSize::to_u16();
        // Can't overflow because enforced on a type level.
        let ell = ((L::to_u16() + b_in_bytes - 1) / b_in_bytes) as u8;
        // Enforced on the type level
        // if ell > 255 {
        //     panic!("ell was too big in expand_message_xmd");
        // }
        let domain = Domain::xmd::<HashT>(dst);
        let b_0 = HashT::new()
            .chain(GenericArray::<u8, HashT::BlockSize>::default())
            .chain(msg)
            .chain(L::to_u16().to_be_bytes())
            .chain([0])
            .chain(domain.data())
            .chain([domain.len()])
            .finalize();

        let b_vals = HashT::new()
            .chain(&b_0[..])
            .chain([1u8])
            .chain(domain.data())
            .chain([domain.len()])
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
