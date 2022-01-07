use core::marker::PhantomData;
use core::ops::Mul;

use super::{Domain, ExpandMsg};
use digest::core_api::BlockSizeUser;
use digest::{Digest, Update};
use generic_array::typenum::{IsLess, IsLessOrEqual, NonZero, Prod, Unsigned, U255, U256, U65536};
use generic_array::{ArrayLength, GenericArray};
use subtle::{Choice, ConditionallySelectable};

/// Placeholder type for implementing expand_message_xmd based on a hash function
pub struct ExpandMsgXmd<HashT>(PhantomData<HashT>)
where
    HashT: Digest + BlockSizeUser + Update,
    HashT::OutputSize: IsLessOrEqual<U256>,
    HashT::OutputSize: IsLessOrEqual<HashT::BlockSize>;

/// ExpandMsgXmd implements expand_message_xmd for the ExpandMsg trait
impl<HashT, L> ExpandMsg<L> for ExpandMsgXmd<HashT>
where
    HashT: Digest + BlockSizeUser + Update,
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
    fn expand_message(msg: &[u8], dst: &[u8]) -> GenericArray<u8, L> {
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

        let mut b_vals = HashT::new()
            .chain(&b_0[..])
            .chain([1u8])
            .chain(domain.data())
            .chain([domain.len()])
            .finalize();

        let mut buf = GenericArray::<_, L>::default();
        let mut offset = 0;

        for i in 1..ell {
            // b_0 XOR b_(idx - 1)
            let tmp: GenericArray<_, HashT::OutputSize> = b_0
                .iter()
                .zip(b_vals.as_slice())
                .map(|(b0val, bi1val)| b0val ^ bi1val)
                .collect();
            for b in b_vals {
                buf[offset % L::to_usize()].conditional_assign(
                    &b,
                    Choice::from(if offset < L::to_usize() { 1 } else { 0 }),
                );
                offset += 1;
            }
            b_vals = HashT::new()
                .chain(tmp)
                .chain([i + 1])
                .chain(domain.data())
                .chain([domain.len()])
                .finalize();
        }
        for b in b_vals {
            buf[offset % L::to_usize()]
                .conditional_assign(&b, Choice::from(if offset < L::to_usize() { 1 } else { 0 }));
            offset += 1;
        }
        buf
    }
}
