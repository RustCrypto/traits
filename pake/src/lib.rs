#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, unused_qualifications)]

use core::fmt;
use kdf::Pbkdf;

/// PAKE algorithm.
pub trait Pake {
    /// Client's proof of validity.
    type ClientProof: AsRef<[u8]> + for<'a> TryFrom<&'a [u8]>;

    /// Handshake state type.
    type HandshakeState: HandshakeState<
            ClientProof = Self::ClientProof,
            ServerProof = Self::ServerProof,
            SharedSecret = Self::SharedSecret,
        >;

    /// Verifier of a given user's identity.
    type UserVerifier: AsRef<[u8]> + for<'a> TryFrom<&'a [u8]>;

    /// Server's proof of validity.
    type ServerProof: AsRef<[u8]> + for<'a> TryFrom<&'a [u8]>;

    /// Server's verifier for client proofs.
    type ServerProofVerifier: ProofVerifier<
            Proof = Self::ClientProof,
            VerificationProof = Self::ServerProof,
            SharedSecret = Self::SharedSecret,
        >;

    /// Shared secret type.
    type SharedSecret: AsRef<[u8]> + for<'a> TryFrom<&'a [u8]>;

    /// Generate the verifier for a given username, password, and salt which can be used in
    /// subsequent password-based authentication attempts.
    fn generate_user_verifier<Kdf: Pbkdf>(
        &self,
        username: &[u8],
        password: &[u8],
        salt: &[u8],
    ) -> Result<Self::UserVerifier>;

    /// Initialize a new handshake state for the given user.
    fn init_handshake(
        &self,
        username: &[u8],
        verifier: &Self::UserVerifier,
    ) -> (Self::HandshakeState, Self::ServerProofVerifier);
}

/// PAKE handshake state obtained from server.
pub trait HandshakeState: for<'a> TryFrom<&'a [u8]> {
    /// Client's proof of validity.
    type ClientProof: AsRef<[u8]> + for<'a> TryFrom<&'a [u8]>;

    /// Client's verifier for the server's proof.
    type ClientProofVerifier: ProofVerifier<
            Proof = Self::ServerProof,
            VerificationProof = Self::ClientProof,
            SharedSecret = Self::SharedSecret,
        >;

    /// Serialization of a handshake.
    type SerializedHandshake: AsRef<[u8]> + for<'a> TryFrom<&'a [u8]>;

    /// Server's proof of validity.
    type ServerProof: AsRef<[u8]> + for<'a> TryFrom<&'a [u8]>;

    /// Shared secret type.
    type SharedSecret: AsRef<[u8]> + for<'a> TryFrom<&'a [u8]>;

    /// Serialize this handshake state as a bytestring.
    fn to_bytes(&self) -> Self::SerializedHandshake;

    /// Generate the client-side proof.
    fn client_proof<Kdf: Pbkdf>(
        &self,
        username: &[u8],
        password: &[u8],
        salt: &[u8],
    ) -> Result<(Self::ClientProof, Self::ClientProofVerifier)>;
}

/// Proof verifier which outputs a shared secret upon success.
pub trait ProofVerifier {
    /// Proof type to be verified.
    type Proof: AsRef<[u8]>;

    /// Proof we correctly verified the input proof.
    type VerificationProof: AsRef<[u8]> + for<'a> TryFrom<&'a [u8]>;

    /// Shared secret to be output upon success.
    type SharedSecret: AsRef<[u8]> + for<'a> TryFrom<&'a [u8]>;

    /// Verify the given proof, returning a shared secret upon success.
    fn verify_proof(
        &self,
        proof: &Self::Proof,
    ) -> Result<(Self::VerificationProof, Self::SharedSecret)>;
}

/// PAKE errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PAKE error")
    }
}

impl core::error::Error for Error {}

/// Result type with the `pake` crate's [`Error`].
pub type Result<T> = core::result::Result<T, Error>;
