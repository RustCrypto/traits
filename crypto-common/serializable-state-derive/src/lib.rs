extern crate proc_macro;

use darling::FromDeriveInput;
use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote, quote_spanned};
use syn::{
    parse_macro_input, punctuated::Iter, spanned::Spanned, Data, DeriveInput, Field, Fields,
    Generics, Index,
};

const CRATE_NAME: &str = "crypto_common";

#[derive(FromDeriveInput, Default)]
#[darling(default, attributes(serializable_state))]
struct Opts {
    crate_path: Option<String>,
}

#[proc_macro_derive(SerializableState, attributes(serializable_state))]
pub fn derive_serializable_state(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input);
    let crate_path = get_crate_path(&input);
    let struct_name = input.ident;

    let serialized_state_size = generate_serializable_state_size(&input.data, &crate_path);
    let serialize_logic = generate_serialize_logic(&input.data);
    let deserialize_logic = generate_deserialize_logic(&input.data);

    check_generics(&input.generics);

    let expanded = quote! {
        impl #crate_path::SerializableState for #struct_name {
            type SerializedStateSize = #serialized_state_size;

            fn serialize(&self) -> #crate_path::SerializedState<Self> {
                use #crate_path::{SerializableState, SerializedState};

                #serialize_logic
            }

            fn deserialize(_serialized_state: &#crate_path::SerializedState<Self>) -> ::core::result::Result<Self, #crate_path::DeserializeStateError> {
                use #crate_path::SerializableState;

                #deserialize_logic
            }
        }
    };

    proc_macro::TokenStream::from(expanded)
}

fn check_generics(generics: &Generics) {
    if generics.params.iter().next().is_some() {
        panic!("Generics are not supported yet. Please implement SerializableState on your own.")
    }
}

fn generate_serializable_state_size(data: &Data, crate_path: &TokenStream) -> TokenStream {
    match *data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => {
                serializable_state_size_from_fields(fields.named.iter(), crate_path)
            }
            Fields::Unnamed(ref fields) => {
                serializable_state_size_from_fields(fields.unnamed.iter(), crate_path)
            }
            Fields::Unit => quote! { #crate_path::typenum::U0 },
        },
        Data::Enum(_) | Data::Union(_) => unimplemented!(),
    }
}

fn generate_serialize_logic(data: &Data) -> TokenStream {
    match *data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => serialize_logic_from_fields(fields.named.iter()),
            Fields::Unnamed(ref fields) => serialize_logic_from_fields(fields.unnamed.iter()),
            Fields::Unit => quote! { SerializedState::<Self>::default() },
        },
        Data::Enum(_) | Data::Union(_) => unimplemented!(),
    }
}

fn generate_deserialize_logic(data: &Data) -> TokenStream {
    match *data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => deserialize_logic_from_fields(fields.named.iter(), true),
            Fields::Unnamed(ref fields) => {
                deserialize_logic_from_fields(fields.unnamed.iter(), false)
            }
            Fields::Unit => quote! { Ok(Self {}) },
        },
        Data::Enum(_) | Data::Union(_) => unimplemented!(),
    }
}

fn serializable_state_size_from_fields(
    mut fields: Iter<Field>,
    crate_path: &TokenStream,
) -> TokenStream {
    match fields.next() {
        None => quote! { #crate_path::typenum::U0 },
        Some(first) => {
            let ty = &first.ty;
            let mut size = quote_spanned! { first.span() => <#ty as #crate_path::SerializableState>::SerializedStateSize };
            fields.for_each(|field| {
                let ty = &field.ty;
                size = quote_spanned! {
                    field.span() => #crate_path::typenum::Sum<<#ty as #crate_path::SerializableState>::SerializedStateSize, #size>
                };
            });
            size
        }
    }
}

fn serialize_logic_from_fields(mut fields: Iter<Field>) -> TokenStream {
    match fields.next() {
        None => quote! { SerializedState::<Self>::default() },
        Some(first) => {
            let field_name = get_field_name(0, &first.ident, None);
            let mut code = quote! { self.#field_name.serialize() };
            fields.enumerate().for_each(|(i, field)| {
                let field_name = get_field_name(i + 1, &field.ident, None);
                code =
                    quote_spanned! { field.span() => #code.concat(self.#field_name.serialize()) };
            });
            code
        }
    }
}

fn deserialize_logic_from_fields(fields: Iter<Field>, named: bool) -> TokenStream {
    let mut skip_first = fields.clone();
    match skip_first.next() {
        None => quote! { Ok(Self {}) },
        Some(first) => {
            let mut code = quote!();
            fields.enumerate().for_each(|(i, field)| {
                let field_name = get_field_name(i, &field.ident, Some("serialized_"));
                let ty = &field.ty;
                code = quote_spanned! {
                    field.span() =>
                    #code
                    let (#field_name, _serialized_state) = _serialized_state.split_ref::<<#ty as SerializableState>::SerializedStateSize>();
                    let #field_name = <#ty>::deserialize(#field_name)?;
                };
            });
            let first = get_field_name(0, &first.ident, Some("serialized_"));
            let recurce = skip_first.enumerate().map(|(i, field)| {
                let field_name = get_field_name(i + 1, &field.ident, Some("serialized_"));
                quote_spanned! { field.span() =>  #field_name }
            });

            let construction = if named {
                quote! { Self { #first #(, #recurce)* } }
            } else {
                quote! { Self ( #first #(, #recurce)* ) }
            };

            quote! {
                #code

                Ok(#construction)
            }
        }
    }
}

fn get_field_name(i: usize, ident: &Option<Ident>, unnamed_prefix: Option<&str>) -> TokenStream {
    match ident {
        Some(ident) => quote! { #ident },
        None => match unnamed_prefix {
            None => {
                let index = Index::from(i);
                quote! { #index }
            }
            Some(unnamed_prefix) => {
                let ident = format_ident!("{}{}", unnamed_prefix, i);
                quote! { #ident }
            }
        },
    }
}

fn get_crate_path(input: &DeriveInput) -> TokenStream {
    let crate_path = format_ident!(
        "{}",
        Opts::from_derive_input(input)
            .expect("Unknown options")
            .crate_path
            .unwrap_or(CRATE_NAME.into())
    );
    quote! { #crate_path }
}
