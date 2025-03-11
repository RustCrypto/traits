use crate::error;

#[cfg(feature = "digest")]
use crate::digest::Digest;

#[cfg(feature = "digest")]
pub trait Verifier<D: Digest, P> {
    fn verify(&self, input: &[u8], proof: P) -> (bool, D);

    fn proof_to_hash(proof: P) -> D;
}
