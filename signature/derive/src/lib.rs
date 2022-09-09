#![crate_type = "proc-macro"]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(
    clippy::unwrap_used,
    rust_2018_idioms,
    trivial_casts,
    unused_import_braces,
    unused_qualifications
)]

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Ident, TypeParam};

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
#[proc_macro_derive(Signer)]
pub fn derive_signer(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    emit_signer_impl(input).into()
}

fn emit_signer_impl(input: DeriveInput) -> TokenStream2 {
    let params = DeriveParams::new(input);
    let ident = &params.ident;
    let type_params = &params.type_params;
    let type_idents = params.type_idents();

    quote! {
        impl<S, #(#type_params),*> ::signature::Signer<S> for #ident<#(#type_idents),*>
        where
            S: ::signature::PrehashSignature,
            Self: ::signature::DigestSigner<S::Digest, S>
        {
            fn try_sign(&self, msg: &[u8]) -> ::signature::Result<S> {
                self.try_sign_digest(S::Digest::new_with_prefix(msg))
            }
        }
    }
}

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
#[proc_macro_derive(Verifier)]
pub fn derive_verifier(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    emit_verifier_impl(input).into()
}

fn emit_verifier_impl(input: DeriveInput) -> TokenStream2 {
    let params = DeriveParams::new(input);
    let ident = &params.ident;
    let type_params = &params.type_params;
    let type_idents = params.type_idents();

    quote! {
        impl<S, #(#type_params),*> ::signature::Verifier<S> for #ident<#(#type_idents),*>
        where
            S: ::signature::PrehashSignature,
            Self: ::signature::DigestVerifier<S::Digest, S>
        {
            fn verify(&self, msg: &[u8], signature: &S) -> ::signature::Result<()> {
                self.verify_digest(S::Digest::new_with_prefix(msg), signature)
            }
        }
    }
}

/// Derive the [`DigestSigner`] trait for a type which impls [`PrehashSigner`].
///
/// [`DigestSigner`]: https://docs.rs/signature/latest/signature/trait.DigestSigner.html
/// [`PrehashSigner`]: https://docs.rs/signature/latest/signature/hazmat/trait.PrehashSigner.html
#[proc_macro_derive(DigestSigner)]
pub fn derive_digest_signer(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    emit_digest_signer_impl(input).into()
}

fn emit_digest_signer_impl(input: DeriveInput) -> TokenStream2 {
    let params = DeriveParams::new(input);
    let ident = &params.ident;
    let type_params = &params.type_params;
    let type_idents = params.type_idents();

    quote! {
        impl<D, S, #(#type_params),*> ::signature::DigestSigner<D, S> for #ident<#(#type_idents),*>
        where
            D: ::signature::digest::Digest,
            S: ::signature::Signature,
            Self: ::signature::hazmat::PrehashSigner<S>
        {
            fn try_sign_digest(&self, digest: D) -> ::signature::Result<S> {
                self.sign_prehash(&digest.finalize())
            }
        }
    }
}

/// Derive the [`DigestVerifier`] trait for a type which impls [`PrehashVerifier`].
///
/// [`DigestVerifier`]: https://docs.rs/signature/latest/signature/trait.DigestVerifier.html
/// [`PrehashVerifier`]: https://docs.rs/signature/latest/signature/hazmat/trait.PrehashVerifier.html
#[proc_macro_derive(DigestVerifier)]
pub fn derive_digest_verifier(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    emit_digest_verifier_impl(input).into()
}

fn emit_digest_verifier_impl(input: DeriveInput) -> TokenStream2 {
    let params = DeriveParams::new(input);
    let ident = &params.ident;
    let type_params = &params.type_params;
    let type_idents = params.type_idents();

    quote! {
        impl<D, S, #(#type_params),*> ::signature::DigestVerifier<D, S> for #ident<#(#type_idents),*>
        where
            D: ::signature::digest::Digest,
            S: ::signature::Signature,
            Self: ::signature::hazmat::PrehashVerifier<S>
        {
            fn verify_digest(&self, digest: D, signature: &S) -> ::signature::Result<()> {
                self.verify_prehash(&digest.finalize(), signature)
            }
        }
    }
}

/// Derivation parameters parsed from `DeriveInput`.
struct DeriveParams {
    /// `Ident` for the struct the trait impls are being added to.
    ident: Ident,

    /// Generic type parameters.
    type_params: Vec<TypeParam>,
}

impl DeriveParams {
    /// Parse parameters from `DeriveInput`.
    fn new(input: DeriveInput) -> Self {
        Self {
            ident: input.ident,
            type_params: input.generics.type_params().cloned().collect(),
        }
    }

    /// Get the `Ident`s which correspond to each of the `type_params`.
    fn type_idents(&self) -> Vec<Ident> {
        self.type_params
            .iter()
            .map(|bound| bound.ident.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    #[test]
    fn signer() {
        let input = parse_quote! {
            #[derive(Signer)]
            struct MySigner<C: EllipticCurve> {
                scalar: Scalar<C::ScalarSize>
            }
        };

        let output = emit_signer_impl(input);

        assert_eq!(
            output.to_string(),
            quote! {
                impl<S, C: EllipticCurve> ::signature::Signer<S> for MySigner<C>
                where
                    S: ::signature::PrehashSignature,
                    Self: ::signature::DigestSigner<S::Digest, S>
                {
                    fn try_sign(&self, msg: &[u8]) -> ::signature::Result<S> {
                        self.try_sign_digest(S::Digest::new_with_prefix(msg))
                    }
                }
            }
            .to_string()
        );
    }

    #[test]
    fn verifier() {
        let input = parse_quote! {
            #[derive(Verifier)]
            struct MyVerifier<C: EllipticCurve> {
                point: UncompressedPoint<C>
            }
        };

        let output = emit_verifier_impl(input);

        assert_eq!(
            output.to_string(),
            quote! {
                impl<S, C: EllipticCurve> ::signature::Verifier<S> for MyVerifier<C>
                where
                    S: ::signature::PrehashSignature,
                    Self: ::signature::DigestVerifier<S::Digest, S>
                {
                    fn verify(&self, msg: &[u8], signature: &S) -> ::signature::Result<()> {
                        self.verify_digest(S::Digest::new_with_prefix(msg), signature)
                    }
                }
            }
            .to_string()
        );
    }

    #[test]
    fn digest_signer() {
        let input = parse_quote! {
            #[derive(DigestSigner)]
            struct MySigner<C: EllipticCurve> {
                scalar: Scalar<C::ScalarSize>
            }
        };

        let output = emit_digest_signer_impl(input);

        assert_eq!(
            output.to_string(),
            quote! {
                impl<D, S, C: EllipticCurve> ::signature::DigestSigner<D, S> for MySigner<C>
                where
                    S: ::signature::Signature,
                    Self: ::signature::hazmat::PrehashSigner<S>
                {
                    fn try_sign_digest(&self, digest: D) -> ::signature::Result<S> {
                        self.sign_prehash(&digest.finalize())
                    }
                }
            }
            .to_string()
        );
    }

    #[test]
    fn digest_verifier() {
        let input = parse_quote! {
            #[derive(DigestVerifier)]
            struct MyVerifier<C: EllipticCurve> {
                point: UncompressedPoint<C>
            }
        };

        let output = emit_digest_verifier_impl(input);

        assert_eq!(
            output.to_string(),
            quote! {
                impl<D, S, C: EllipticCurve> ::signature::DigestVerifier<D, S> for MyVerifier<C>
                where
                    S: ::signature::Signature,
                    Self: ::signature::hazmat::PrehashVerifier<S>
                {
                    fn verify_digest(&self, digest: D) -> ::signature::Result<S> {
                        self.verify_prehash(&digest.finalize())
                    }
                }
            }
            .to_string()
        );
    }
}
