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
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{
    parse_macro_input, parse_quote, punctuated::Punctuated, DeriveInput, Ident, PredicateType,
    Token, TraitBound, Type, TypeParam, TypeParamBound, WhereClause, WherePredicate,
};

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
    let s_ident = Ident::new("__S", Span::call_site());

    let mut params = DeriveParams::new(input);
    params.add_bound(&s_ident, parse_quote!(::signature::PrehashSignature));
    params.add_bound(
        &Ident::new("Self", Span::call_site()),
        parse_quote!(::signature::DigestSigner<#s_ident::Digest, #s_ident>),
    );

    let name = params.name;
    let impl_generics = params.impl_generics;
    let ty_generics = params.ty_generics;
    let where_clause = params.where_clause;

    quote! {
        impl<#(#impl_generics),*> ::signature::Signer<#s_ident> for #name<#(#ty_generics),*>
        #where_clause
        {
            fn try_sign(&self, msg: &[u8]) -> ::signature::Result<#s_ident> {
                self.try_sign_digest(#s_ident::Digest::new_with_prefix(msg))
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
    let s_ident = Ident::new("__S", Span::call_site());

    let mut params = DeriveParams::new(input);
    params.add_bound(&s_ident, parse_quote!(::signature::PrehashSignature));
    params.add_bound(
        &Ident::new("Self", Span::call_site()),
        parse_quote!(::signature::DigestVerifier<#s_ident::Digest, #s_ident>),
    );

    let name = params.name;
    let impl_generics = params.impl_generics;
    let ty_generics = params.ty_generics;
    let where_clause = params.where_clause;

    quote! {
        impl<#(#impl_generics),*> ::signature::Verifier<#s_ident> for #name<#(#ty_generics),*>
        #where_clause
        {
            fn verify(&self, msg: &[u8], signature: &#s_ident) -> ::signature::Result<()> {
                self.verify_digest(#s_ident::Digest::new_with_prefix(msg), signature)
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
    let d_ident = Ident::new("__D", Span::call_site());
    let s_ident = Ident::new("__S", Span::call_site());

    let mut params = DeriveParams::new(input);
    params.add_bound(&d_ident, parse_quote!(::signature::digest::Digest));
    params.add_bound(&s_ident, parse_quote!(::signature::Signature));
    params.add_bound(
        &Ident::new("Self", Span::call_site()),
        parse_quote!(::signature::hazmat::PrehashSigner<#s_ident>),
    );

    let name = params.name;
    let impl_generics = params.impl_generics;
    let ty_generics = params.ty_generics;
    let where_clause = params.where_clause;

    quote! {
        impl<#(#impl_generics),*> ::signature::DigestSigner<#d_ident, #s_ident> for #name<#(#ty_generics),*>
        #where_clause
        {
            fn try_sign_digest(&self, digest: #d_ident) -> ::signature::Result<#s_ident> {
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
    let d_ident = Ident::new("__D", Span::call_site());
    let s_ident = Ident::new("__S", Span::call_site());

    let mut params = DeriveParams::new(input);
    params.add_bound(&d_ident, parse_quote!(::signature::digest::Digest));
    params.add_bound(&s_ident, parse_quote!(::signature::Signature));
    params.add_bound(
        &Ident::new("Self", Span::call_site()),
        parse_quote!(::signature::hazmat::PrehashVerifier<#s_ident>),
    );

    let name = params.name;
    let impl_generics = params.impl_generics;
    let ty_generics = params.ty_generics;
    let where_clause = params.where_clause;

    quote! {
        impl<#(#impl_generics),*> ::signature::DigestVerifier<#d_ident, #s_ident> for #name<#(#ty_generics),*>
        #where_clause
        {
            fn verify_digest(&self, digest: #d_ident, signature: &#s_ident) -> ::signature::Result<()> {
                self.verify_prehash(&digest.finalize(), signature)
            }
        }
    }
}

/// Derivation parameters parsed from `DeriveInput`.
struct DeriveParams {
    /// Name of the struct the trait impls are being added to.
    name: Ident,

    /// Generic parameters of `impl`.
    impl_generics: Vec<TypeParam>,

    /// Generic parameters of the type.
    ty_generics: Vec<Ident>,

    /// Where clause in-progress.
    where_clause: WhereClause,
}

impl DeriveParams {
    /// Parse parameters from `DeriveInput`.
    fn new(input: DeriveInput) -> Self {
        let impl_generics = input.generics.type_params().cloned().collect();

        let ty_generics = input
            .generics
            .type_params()
            .map(|bound| bound.ident.clone())
            .collect();

        let where_clause = input
            .generics
            .where_clause
            .clone()
            .unwrap_or_else(|| WhereClause {
                where_token: <Token![where]>::default(),
                predicates: Punctuated::new(),
            });

        Self {
            name: input.ident,
            impl_generics,
            ty_generics,
            where_clause,
        }
    }

    /// Add a generic parameter with the given bound.
    fn add_bound(&mut self, name: &Ident, bound: TraitBound) {
        if name != "Self" {
            self.impl_generics.push(TypeParam {
                attrs: vec![],
                ident: name.clone(),
                colon_token: None,
                bounds: Default::default(),
                eq_token: None,
                default: None,
            });
        }

        let type_path = parse_quote!(#name);

        let mut bounds = Punctuated::new();
        bounds.push(TypeParamBound::Trait(bound));

        let predicate_type = PredicateType {
            lifetimes: None,
            bounded_ty: Type::Path(type_path),
            colon_token: <Token![:]>::default(),
            bounds,
        };

        self.where_clause
            .predicates
            .push(WherePredicate::Type(predicate_type))
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
            struct MySigner<C>
            where
                C: EllipticCurve
            {
                scalar: Scalar<C::ScalarSize>
            }
        };

        let output = emit_signer_impl(input);

        assert_eq!(
            output.to_string(),
            quote! {
                impl<C, __S> ::signature::Signer<__S> for MySigner<C>
                where
                    C: EllipticCurve,
                    __S: ::signature::PrehashSignature,
                    Self: ::signature::DigestSigner<__S::Digest, __S>
                {
                    fn try_sign(&self, msg: &[u8]) -> ::signature::Result<__S> {
                        self.try_sign_digest(__S::Digest::new_with_prefix(msg))
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
                impl<C: EllipticCurve, __S> ::signature::Verifier<__S> for MyVerifier<C>
                where
                    __S: ::signature::PrehashSignature,
                    Self: ::signature::DigestVerifier<__S::Digest, __S>
                {
                    fn verify(&self, msg: &[u8], signature: &__S) -> ::signature::Result<()> {
                        self.verify_digest(__S::Digest::new_with_prefix(msg), signature)
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
                impl<C: EllipticCurve, __D, __S> ::signature::DigestSigner<__D, __S> for MySigner<C>
                where
                    __D: ::signature::digest::Digest,
                    __S: ::signature::Signature,
                    Self: ::signature::hazmat::PrehashSigner<__S>
                {
                    fn try_sign_digest(&self, digest: __D) -> ::signature::Result<__S> {
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
                impl<C: EllipticCurve, __D, __S> ::signature::DigestVerifier<__D, __S> for MyVerifier<C>
                where
                    __D: ::signature::digest::Digest,
                    __S: ::signature::Signature,
                    Self: ::signature::hazmat::PrehashVerifier<__S>
                {
                    fn verify_digest(&self, digest: __D, signature: &__S) -> ::signature::Result<()> {
                        self.verify_prehash(&digest.finalize(), signature)
                    }
                }
            }
            .to_string()
        );
    }
}
