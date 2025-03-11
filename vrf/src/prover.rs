use crate::error;

#[cfg(feature = "digest")]
use crate::digest::Digest;

#[cfg(feature = "digest")]
pub trait Prover<D: Digest, P> {
    fn prove(&self, input: &[u8]) -> error::Result<P>;

    fn proof_to_hash(proof: P) -> D;
}
