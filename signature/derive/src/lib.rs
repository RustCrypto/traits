//! Custom derive support for the `signature` crate.
//!
//! This crate can be used to derive `Signer` and `Verifier` impls for
//! types that impl `DigestSigner` or `DigestVerifier` respectively.

#![crate_type = "proc-macro"]
#![recursion_limit = "128"]
#![deny(warnings, unused_import_braces, unused_qualifications)]
#![forbid(unsafe_code)]

extern crate proc_macro;

use proc_macro2::TokenStream;
use quote::quote;
use synstructure::{decl_derive, AddBounds};

/// Derive the `Signer` trait for `DigestSigner` types
fn derive_signer(mut s: synstructure::Structure) -> TokenStream {
    s.add_bounds(AddBounds::None);
    s.gen_impl(quote! {
        gen impl<S> signature::Signer<S> for @Self
        where
            S: signature::PrehashSignature,
            Self: signature::DigestSigner<S::Digest, S>
        {
            fn try_sign(&self, msg: &[u8]) -> Result<S, signature::Error> {
                self.try_sign_digest(S::Digest::new().chain(msg))
            }
        }
    })
}

decl_derive! {
    [Signer] =>
    /// Derive the [`Signer`] trait for a type which impls [`DigestSigner`].
    ///
    /// When implementing the [`DigestSigner`] trait for a signature type which
    /// itself impl's the [`PrehashSignature`] trait (which marks signature
    /// algorithms which are computed using a [`Digest`]), signature providers
    /// can automatically derive the [`Signer`] trait when the digest algorithm
    /// is [`PrehashSignature::Digest`] (i.e. the "standard" digest algorithm
    /// for a given signature type)
    ///
    /// This automates all of the digest computation otherwise needed for a
    /// complete signature algorithm implementation.
    ///
    /// [`Digest`]: https://docs.rs/digest/latest/digest/trait.Digest.html
    /// [`DigestSigner`]: https://docs.rs/signature/latest/signature/trait.DigestSigner.html
    /// [`PrehashSignature`]: https://docs.rs/signature/latest/signature/trait.PrehashSignature.html
    /// [`PrehashSignature::Digest`]: https://docs.rs/signature/latest/signature/trait.PrehashSignature.html#associated-types
    derive_signer
}

/// Derive the `Verifier` trait for `DigestVerifier` types
fn derive_verifier(mut s: synstructure::Structure) -> TokenStream {
    s.add_bounds(AddBounds::None);
    s.gen_impl(quote! {
        gen impl<S> signature::Verifier<S> for @Self
        where
            S: signature::PrehashSignature,
            Self: signature::DigestVerifier<S::Digest, S>
        {
            fn verify(&self, msg: &[u8], signature: &S) -> Result<(), signature::Error> {
                self.verify_digest(S::Digest::new().chain(msg), signature)
            }
        }
    })
}

decl_derive! {
    [Verifier] =>
    /// Derive the [`Verifier`] trait for a type which impls [`DigestVerifier`].
    ///
    /// When implementing the [`DigestVerifier`] trait for a signature type which
    /// itself impl's the [`PrehashSignature`] trait (which marks signature
    /// algorithms which are computed using a [`Digest`]), signature providers
    /// can automatically derive the [`Verifier`] trait when the digest algorithm
    /// is [`PrehashSignature::Digest`] (i.e. the "standard" digest algorithm
    /// for a given signature type)
    ///
    /// This automates all of the digest computation otherwise needed for a
    /// complete signature algorithm implementation.
    ///
    /// [`Digest`]: https://docs.rs/digest/latest/digest/trait.Digest.html
    /// [`DigestVerifier`]: https://docs.rs/signature/latest/signature/trait.DigestVerifier.html
    /// [`PrehashSignature`]: https://docs.rs/signature/latest/signature/trait.PrehashSignature.html
    /// [`PrehashSignature::Digest`]: https://docs.rs/signature/latest/signature/trait.PrehashSignature.html#associated-types
    derive_verifier
}

#[cfg(test)]
mod tests {
    use super::*;
    use synstructure::test_derive;

    #[test]
    fn signer() {
        test_derive! {
            derive_signer {
                struct MySigner<C: EllipticCurve> {
                    scalar: Scalar<C::ScalarSize>
                }
            }
            expands to {
                #[allow(non_upper_case_globals)]
                const _DERIVE_signature_Signer_S_FOR_MySigner: () = {
                    impl<S, C: EllipticCurve> signature::Signer<S> for MySigner<C>
                    where
                        S: signature::PrehashSignature,
                        Self: signature::DigestSigner<S::Digest, S>
                    {
                        fn try_sign(&self, msg: &[u8]) -> Result <S, signature::Error> {
                            self.try_sign_digest(S::Digest::new().chain(msg))
                        }
                    }
                };
            }
            no_build // tests in `signature-crate/tests`
        }
    }

    #[test]
    fn verifier() {
        test_derive! {
            derive_verifier {
                struct MyVerifier<C: EllipticCurve> {
                    point: UncompressedPoint<C>
                }
            }
            expands to {
                #[allow(non_upper_case_globals)]
                const _DERIVE_signature_Verifier_S_FOR_MyVerifier: () = {
                    impl<S, C: EllipticCurve> signature::Verifier<S> for MyVerifier<C>
                    where
                        S: signature::PrehashSignature,
                        Self: signature::DigestVerifier<S::Digest, S>
                    {
                        fn verify(&self, msg: &[u8], signature: &S) -> Result<(), signature::Error> {
                            self.verify_digest(S::Digest::new().chain(msg), signature)
                        }
                    }
                };
            }
            no_build // tests in `signature-crate/tests`
        }
    }
}
