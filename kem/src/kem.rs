//! KEM Traits

use crate::errors::Error;
use core::fmt::Debug;
use generic_array::{ArrayLength, GenericArray};

use rand_core::{CryptoRng, RngCore};

/// Trait impl'd by concrete types that represent an encapsulated key. This is intended to be, in
/// essence, a bag of bytes.
pub trait EncappedKey: AsRef<[u8]> + Debug + Sized {
    /// The size, in bytes, of an encapsulated key.
    type NEnc: ArrayLength<u8>;

    /// The size, in bytes, of the shared secret that this KEM produces.
    type NSecret: ArrayLength<u8>;

    /// Represents the identity key of an encapsulator. This is used in authenticated
    /// decapsulation.
    type SenderPublicKey;

    /// The public key of a decapsulator. This is used in encapsulation.
    type RecipientPublicKey;

    /// Parses an encapsulated key from its byte representation.
    fn from_bytes(bytes: &GenericArray<u8, Self::NEnc>) -> Result<Self, Error>;

    /// Borrows a byte slice representing the serialized form of this encapsulated key.
    fn as_bytes(&self) -> &GenericArray<u8, Self::NEnc> {
        // EncappedKey is already AsRef<[u8]>, so we don't need to do any work. This will panic iff
        // the underlying bytestring is not precisely NEnc bytes long.
        self.as_ref().into()
    }
}

/// Represents the functionality of a key encapsulator. For unauthenticated encapsulation, `Self`
/// can be an empty struct. For authenticated encapsulation, `Self` is a private key.
pub trait Encapsulator<EK: EncappedKey> {
    /// Attempts to encapsulate a fresh shared secret with the given recipient. The resulting
    /// shared secret is bound to the identity encoded in `Self` (i.e., authenticated wrt `Self`).
    /// If `Self` is empty, then this is equivalent to unauthenticated encapsulation. Returns the
    /// shared secret and encapsulated key on success, or an error if something went wrong.
    fn try_encap<R: CryptoRng + RngCore>(
        &self,
        csprng: &mut R,
        recip_pubkey: &EK::RecipientPublicKey,
    ) -> Result<(EK, GenericArray<u8, EK::NSecret>), Error>;
}

/// Represents the functionality of a key decapsulator, where `Self` is a cryptographic key.
pub trait Decapsulator<EK: EncappedKey> {
    /// Attempt to decapsulate the given encapsulated key. Returns the shared secret on success, or
    /// an error if something went wrong.
    fn try_decap(&self, encapped_key: &EK) -> Result<GenericArray<u8, EK::NSecret>, Error>;
}

/// Represents the functionality of a authenticated-key decapsulator, where `Self` is a
/// cryptographic key.
pub trait AuthDecapsulator<EK: EncappedKey> {
    /// Attempt to decapsulate the given encapsulated key. The resulting shared secret is bound to
    /// the provided sender identity, thus providing authenticity. Returns the shared secret
    /// success, or an error if something went wrong.
    fn try_auth_decap(
        &self,
        encapped_key: &EK,
        sender_pubkey: &EK::SenderPublicKey,
    ) -> Result<GenericArray<u8, EK::NSecret>, Error>;
}
