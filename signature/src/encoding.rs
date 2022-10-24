//! Encoding support.

use crate::{Error, Result};

/// Support for decoding/encoding signatures as bytes.
pub trait SignatureEncoding:
    Clone + Sized + for<'a> TryFrom<&'a [u8], Error = Error> + Into<Self::Repr>
{
    /// Byte representation of a signature.
    type Repr: 'static + AsRef<[u8]> + AsMut<[u8]> + Clone + Default + Send + Sync;

    /// Decode signature from its byte representation.
    fn from_bytes(bytes: &Self::Repr) -> Result<Self> {
        Self::try_from(bytes.as_ref())
    }

    /// Encode signature as its byte representation.
    fn to_bytes(&self) -> Self::Repr {
        self.clone().into()
    }
}
