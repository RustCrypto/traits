//! KEM Traits

use crate::errors::Error;
use core::fmt::Debug;
use generic_array::{ArrayLength, GenericArray};

use rand_core::{CryptoRng, RngCore};

/// Trait impl'd by concrete types that represent encapsulated keys. Besides encoding the behavior
/// of the encapsulated key, this also requires
pub trait EncappedKey: AsRef<[u8]> + Debug + Sized {
    /// The size of the shared secret that this KEM produces
    type NSecret: ArrayLength<u8>;

    /// The public key type of this KEM. This is used for encapsulation and authenticated
    /// decapsulation.
    type PublicKey: AsRef<[u8]> + Debug + Sized;

    /// Parse an encapsulated key from its byte representation
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error>;

    /// Borrow a byte slice representing the serialized form of this
    /// encapsulated key
    fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}

/// Represents the functionality of a key encapsulator. For unauthenticated encapsulation, `Self`
/// can be an empty struct. For authenticated encapsulation, `Self` is a private key.
pub trait Encapsulator<EK: EncappedKey> {
    /// Attempt to encapsulate a fresh shared secret with the given recipient. The resulting shared
    /// secret is bound to the identity encoded in `Self` (i.e., authenticated wrt `Self`). If
    /// `Self` is empty, then this is equivalent to unauthenticated encapsulation. Returns the
    /// shared secret and encapsulated key on success, or an error if something went wrong.
    fn try_encap<R>(
        &self,
        csprng: &mut R,
        recip_pubkey: &EK::PublicKey,
    ) -> Result<(EK, GenericArray<u8, EK::NSecret>), Error>
    where
        R: CryptoRng + RngCore;
}

/// Represents the functionality of a key decapsulator, where `Self` is a cryptographic key
pub trait Decapsulator<EK: EncappedKey> {
    /// Attempt to decapsulate the given encapsulated key. Returns the shared secret on success, or
    /// an error if something went wrong.
    fn try_decap(&self, encapped_key: &EK) -> Result<GenericArray<u8, EK::NSecret>, Error>;
}

/// Represents the functionality of a authenticated-key decapsulator, where `Self` is a
/// cryptographic key
pub trait AuthDecapsulator<EK>
where
    EK: EncappedKey,
{
    /// Attempt to decapsulate the given encapsulated key. The resulting shared secret is bound to
    /// the provided sender identity, thus providing authenticity. Returns the shared secret
    /// success, or an error if something went wrong.
    fn try_auth_decap(
        &self,
        encapped_key: &EK,
        sender_pubkey: &EK::PublicKey,
    ) -> Result<GenericArray<u8, EK::NSecret>, Error>;
}
