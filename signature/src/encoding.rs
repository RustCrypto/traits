//! Encoding support.

use crate::{Error, Result};

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, vec::Vec};

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

    /// Encode signature as a byte vector.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn to_vec(&self) -> Vec<u8> {
        self.to_bytes().as_ref().to_vec()
    }

    /// Encode the signature as a boxed byte slice.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn to_boxed_slice(&self) -> Box<[u8]> {
        self.to_vec().into_boxed_slice()
    }
}
