use crate::{Ident, Output};

/// Trait for hash peppering functions.
pub trait Pepper {
    /// Algorithm-specific errors
    type Error;

    /// Peppers the `data`.
    fn pepper(&self, data: Output) -> Result<Output, Self::Error>;

    /// Verifies that the `data` is peppered to the same as `to_verify`.
    fn verify(&self, data: Output, to_verify: &Output) -> Result<(), Self::Error>;

    /// Identifies the algorithm uniquely.
    fn ident<'a>(&'a self) -> Ident<'a>;
}
