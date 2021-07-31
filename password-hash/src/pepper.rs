use crate::{Ident, Output};

pub trait Pepper {
    type Error;
    fn pepper(&self, data: &[u8]) -> Result<Output, Self::Error>;
    fn verify(&self, deta: &[u8]) -> Result<(), Self::Error>;
    fn ident<'a>(&'a self) -> Ident<'a>;
}
