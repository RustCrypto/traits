//! Traits for generating digital signatures

use crate::error::Error;
use core::convert::Infallible;

#[cfg(feature = "digest")]
use crate::digest::Update;

#[cfg(feature = "rand_core")]
use crate::rand_core::{CryptoRng, TryCryptoRng};

/// Sign the provided message bytestring using `Self` (e.g. a cryptographic key), returning a
/// digital signature.
pub trait Signer<S>: TrySigner<S, Error = Infallible> {
    /// Sign the given message and return a digital signature
    fn sign(&self, msg: &[u8]) -> S;
}

/// Sign the provided message bytestring using `Self` (e.g. a cryptographic key), returning a
/// digital signature on success, or the provided error type.
pub trait TrySigner<S> {
    /// Error type.
    type Error: core::error::Error + Into<Error>;

    /// Attempt to sign the given message, returning a digital signature on success, or an error if
    /// something went wrong.
    ///
    /// The main intended use case for signing errors is when communicating with external signers,
    /// e.g. cloud KMS, HSMs, or other hardware tokens.
    fn try_sign(&self, msg: &[u8]) -> Result<S, Self::Error>;
}

/// Equivalent of [`Signer`] but the message is provided in non-contiguous byte slices.
pub trait MultipartSigner<S> {
    /// Equivalent of [`Signer::sign()`] but the message
    /// is provided in non-contiguous byte slices.
    fn multipart_sign(&self, msg: &[&[u8]]) -> S;
}

pub trait TryMultipartSigner<S> {
    /// Error type.
    type Error: core::error::Error + Into<Error>;

    /// Equivalent of [`Signer::try_sign()`] but the
    /// message is provided in non-contiguous byte slices.
    fn try_multipart_sign(&self, msg: &[&[u8]]) -> Result<S, Self::Error>;
}

/// Sign the provided message bytestring using `&mut Self` (e.g. an evolving
/// cryptographic key such as a stateful hash-based signature), returning a
/// digital signature.
pub trait SignerMut<S> {
    /// Sign the given message, update the state, and return a digital signature.
    fn sign(&mut self, msg: &[u8]) -> S;
}

pub trait TrySignerMut<S> {
    /// Error type.
    type Error: core::error::Error + Into<Error>;

    /// Attempt to sign the given message, updating the state, and returning a digital signature on
    /// success, or an error if something went wrong.
    ///
    /// Signing can fail, e.g. if the number of time periods allowed by the current key is exceeded.
    fn try_sign(&mut self, msg: &[u8]) -> Result<S, Self::Error>;
}

/// Sign the given prehashed message `Digest` using `Self`.
///
/// ## Notes
///
/// This trait is primarily intended for signature algorithms based on the
/// [Fiat-Shamir heuristic], a method for converting an interactive
/// challenge/response-based proof-of-knowledge protocol into an offline
/// digital signature through the use of a random oracle, i.e. a digest
/// function.
///
/// The security of such protocols critically rests upon the inability of
/// an attacker to solve for the output of the random oracle, as generally
/// otherwise such signature algorithms are a system of linear equations and
/// therefore doing so would allow the attacker to trivially forge signatures.
///
/// To prevent misuse which would potentially allow this to be possible, this
/// API accepts a `Digest` instance, rather than a raw digest value.
///
/// [Fiat-Shamir heuristic]: https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic
#[cfg(feature = "digest")]
pub trait DigestSigner<D: Update, S> {
    /// Sign a message by updating the received `Digest` with it,
    /// returning a signature.
    ///
    /// The given function can be invoked multiple times. It is expected that
    /// in each invocation the `Digest` is updated with the entire equal message.
    ///
    /// Panics in the event of a signing error.
    fn sign_digest<F: Fn(&mut D)>(&self, f: F) -> S;
}

#[cfg(feature = "digest")]
pub trait TryDigestSigner<D: Update, S> {
    /// Error type.
    type Error: core::error::Error + Into<Error>;

    /// Attempt to sign a message by updating the received `Digest` with it,
    /// returning a digital signature on success, or an error if something went wrong.
    ///
    /// The given function can be invoked multiple times. It is expected that
    /// in each invocation the `Digest` is updated with the entire equal message.
    fn try_sign_digest<F: Fn(&mut D) -> Result<(), Error>>(&self, f: F) -> Result<S, Self::Error>;
}

/// Sign the given message using the provided external randomness source.
#[cfg(feature = "rand_core")]
pub trait RandomizedSigner<S> {
    /// Sign the given message and return a digital signature
    fn sign_with_rng<R: CryptoRng + ?Sized>(&self, rng: &mut R, msg: &[u8]) -> S;
}

#[cfg(feature = "rand_core")]
pub trait TryRandomizedSigner<S> {
    /// Error type.
    type Error: core::error::Error + Into<Error>;

    /// Attempt to sign the given message, returning a digital signature on
    /// success, or an error if something went wrong.
    ///
    /// The main intended use case for signing errors is when communicating
    /// with external signers, e.g. cloud KMS, HSMs, or other hardware tokens.
    fn try_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<S, Self::Error>;
}

/// Equivalent of [`RandomizedSigner`] but the message is provided in non-contiguous byte slices.
#[cfg(feature = "rand_core")]
pub trait RandomizedMultipartSigner<S> {
    /// Equivalent of [`RandomizedSigner::sign_with_rng`] but the message is provided in
    /// non-contiguous byte slices.
    fn multipart_sign_with_rng<R: CryptoRng + ?Sized>(&self, rng: &mut R, msg: &[&[u8]]) -> S;
}

#[cfg(feature = "rand_core")]
pub trait TryRandomizedMultipartSigner<S> {
    /// Error type.
    type Error: core::error::Error + Into<Error>;

    /// Equivalent of [`RandomizedSigner::try_sign_with_rng`] but the message is provided in
    /// non-contiguous byte slices.
    fn try_multipart_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[&[u8]],
    ) -> Result<S, Self::Error>;
}

/// Combination of [`DigestSigner`] and [`RandomizedSigner`] with support for
/// computing a signature over a digest which requires entropy from an RNG.
#[cfg(all(feature = "digest", feature = "rand_core"))]
pub trait RandomizedDigestSigner<D: Update, S> {
    /// Sign a message by updating the received `Digest` with it,
    /// returning a signature.
    ///
    /// The given function can be invoked multiple times. It is expected that
    /// in each invocation the `Digest` is updated with the entire equal message.
    ///
    /// Panics in the event of a signing error.
    fn sign_digest_with_rng<R: CryptoRng + ?Sized, F: Fn(&mut D)>(&self, rng: &mut R, f: F) -> S;
}

#[cfg(all(feature = "digest", feature = "rand_core"))]
pub trait TryRandomizedDigestSigner<D: Update, S> {
    /// Error type.
    type Error: core::error::Error + Into<Error>;

    /// Attempt to sign a message by updating the received `Digest` with it,
    /// returning a digital signature on success, or an error if something went wrong.
    ///
    /// The given function can be invoked multiple times. It is expected that
    /// in each invocation the `Digest` is updated with the entire equal message.
    fn try_sign_digest_with_rng<
        R: TryCryptoRng + ?Sized,
        F: Fn(&mut D) -> Result<(), Self::Error>,
    >(
        &self,
        rng: &mut R,
        f: F,
    ) -> Result<S, Self::Error>;
}

/// Sign the provided message bytestring using `&mut Self` (e.g. an evolving
/// cryptographic key such as a stateful hash-based signature), and a per-signature
/// randomizer, returning a digital signature.
#[cfg(feature = "rand_core")]
pub trait RandomizedSignerMut<S> {
    /// Sign the given message, update the state, and return a digital signature.
    fn sign_with_rng<R: CryptoRng + ?Sized>(&mut self, rng: &mut R, msg: &[u8]) -> S;
}

#[cfg(feature = "rand_core")]
pub trait TryRandomizedSignerMut<S> {
    /// Error type.
    type Error: core::error::Error + Into<Error>;

    /// Attempt to sign the given message, updating the state, and returning a
    /// digital signature on success, or an error if something went wrong.
    ///
    /// Signing can fail, e.g., if the number of time periods allowed by the
    /// current key is exceeded.
    fn try_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<S, Self::Error>;
}

/// Equivalent of [`RandomizedSignerMut`] but the message is provided in non-contiguous byte slices.
#[cfg(feature = "rand_core")]
pub trait RandomizedMultipartSignerMut<S> {
    /// Equivalent of [`RandomizedSignerMut::sign_with_rng()`] but
    /// the message is provided in non-contiguous byte slices.
    fn multipart_sign_with_rng<R: CryptoRng + ?Sized>(&mut self, rng: &mut R, msg: &[&[u8]]) -> S;
}

#[cfg(feature = "rand_core")]
pub trait TryRandomizedMultipartSignerMut<S> {
    /// Error type.
    type Error: core::error::Error + Into<Error>;

    /// Equivalent of [`RandomizedSignerMut::try_sign_with_rng()`]
    /// but the message is provided in non-contiguous byte slices.
    fn try_multipart_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        msg: &[&[u8]],
    ) -> Result<S, Self::Error>;
}

/// Asynchronously sign the provided message bytestring using `Self`
/// (e.g. client for a Cloud KMS or HSM), returning a digital signature.
///
/// This trait is an async equivalent of the [`Signer`] trait.
pub trait AsyncSigner<S> {
    /// Sign the given message, returning a digital signature.
    async fn sign_async(&self, msg: &[u8]) -> S;
}

pub trait TryAsyncSigner<S> {
    /// Error type.
    type Error: core::error::Error + Into<Error>;

    /// Attempt to sign the given message, returning a digital signature on
    /// success, or an error if something went wrong.
    ///
    /// The main intended use case for signing errors is when communicating
    /// with external signers, e.g. cloud KMS, HSMs, or other hardware tokens.
    async fn try_sign_async(&self, msg: &[u8]) -> Result<S, Self::Error>;
}

/// Asynchronously sign the given prehashed message `Digest` using `Self`.
///
/// This trait is an async equivalent of the [`DigestSigner`] trait.
#[cfg(feature = "digest")]
pub trait AsyncDigestSigner<D, S>
where
    D: Update,
{
    /// Sign a message by updating the received `Digest` with it, returning a digital signature.
    async fn try_sign_digest_async<F>(&self, f: F) -> S
    where
        F: AsyncFn(&mut D);
}

#[cfg(feature = "digest")]
pub trait TryAsyncDigestSigner<D, S>
where
    D: Update,
{
    /// Error type.
    type Error: core::error::Error + Into<Error>;

    /// Attempt to sign a message by updating the received `Digest` with it,
    /// returning a digital signature on success, or an error if something went wrong.
    ///
    /// The given function can be invoked multiple times. It is expected that
    /// in each invocation the `Digest` is updated with the entire equal message.
    async fn try_sign_digest_async<F>(&self, f: F) -> Result<S, Self::Error>
    where
        F: AsyncFn(&mut D) -> Result<(), Self::Error>;
}

/// Sign the given message using the provided external randomness source.
#[cfg(feature = "rand_core")]
pub trait AsyncRandomizedSigner<S> {
    /// Sign the given message and return a digital signature.
    async fn sign_with_rng_async<R: CryptoRng + ?Sized>(&self, rng: &mut R, msg: &[u8]) -> S;
}

#[cfg(feature = "rand_core")]
pub trait TryAsyncRandomizedSigner<S> {
    /// Error type.
    type Error: core::error::Error + Into<Error>;

    /// Attempt to sign the given message, returning a digital signature on
    /// success, or an error if something went wrong.
    ///
    /// The main intended use case for signing errors is when communicating
    /// with external signers, e.g. cloud KMS, HSMs, or other hardware tokens.
    async fn try_sign_with_rng_async<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<S, Self::Error>;
}
