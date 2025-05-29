use digest::{Output, OutputSizeUser};

pub use signature::Verifier;

pub trait Proof<H>
where
    H: OutputSizeUser,
{
    fn to_hash(&self) -> Output<H>;
}

pub trait Prover<H>
where
    H: OutputSizeUser,
{
    type Proof: Proof<H>;

    fn prove(&self, alpha: &[u8]) -> Self::Proof;
}
