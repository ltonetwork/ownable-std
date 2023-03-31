use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, AttributeArgs, Data::{Enum, Struct}, DataEnum, DataStruct, DeriveInput, FieldsNamed};

#[proc_macro_attribute]
pub fn ownables_std_execute_msg(metadata: TokenStream, input: TokenStream) -> TokenStream {
   
    // validate no input args
    let meta_ast = parse_macro_input!(metadata as AttributeArgs);
    if let Some(arg) = meta_ast.first() {
        return syn::Error::new_spanned(arg, "no args expected")
            .to_compile_error()
            .into();
    }

    // define the variants to be inserted and parse into DataEnum
    let default_execute_variants: TokenStream = quote! {
        enum ExecuteMsg { 
            Transfer {to: Addr},
            Lock {},
            Consume {},
        }
    }
    .into();
    let default_ast: DeriveInput = parse_macro_input!(default_execute_variants);
    let default_variants = match default_ast.data {
        Enum(DataEnum { variants, .. }) => variants,
        _ => panic!("only enums can provide variants"),
    };

    // parse the input variants
    let mut input_ast: DeriveInput = parse_macro_input!(input);
    let input_variants_data = match &mut input_ast.data {
        Enum(DataEnum { variants, .. }) => variants,
        _ => panic!("only enums can accept variants")
    };

    // insert variants from the default to input
    input_variants_data.extend(default_variants.into_iter());

    quote! { #input_ast }.into()
}

#[proc_macro_attribute]
pub fn ownables_std_query_msg(metadata: TokenStream, input: TokenStream) -> TokenStream {
   
    // validate no input args
    let meta_ast = parse_macro_input!(metadata as AttributeArgs);
    if let Some(arg) = meta_ast.first() {
        return syn::Error::new_spanned(arg, "no args expected")
            .to_compile_error()
            .into();
    }

    // define the variants to be inserted and parse into DataEnum
    let default_query_variants: TokenStream = quote! {
        enum QueryMsg { 
            GetInfo {},
            GetMetadata {},
            GetWidgetState {},
            IsLocked {},
            IsConsumerOf {
                issuer: Addr,
                consumable_type: String,
            },
        }
    }
    .into();
    let default_ast: DeriveInput = parse_macro_input!(default_query_variants);
    let default_variants = match default_ast.data {
        Enum(DataEnum { variants, .. }) => variants,
        _ => panic!("only enums can provide variants"),
    };

    // parse the input variants
    let mut input_ast: DeriveInput = parse_macro_input!(input);
    let input_variants_data = match &mut input_ast.data {
        Enum(DataEnum { variants, .. }) => variants,
        _ => panic!("only enums can accept variants")
    };

    // insert variants from the default to input
    input_variants_data.extend(default_variants.into_iter());

    quote! { #input_ast }.into()
}

#[proc_macro_attribute]
pub fn ownables_std_instantiate_msg(metadata: TokenStream, input: TokenStream) -> TokenStream {
    // validate no input args
    let meta_ast = parse_macro_input!(metadata as AttributeArgs);
    if let Some(arg) = meta_ast.first() {
        return syn::Error::new_spanned(arg, "no args expected")
            .to_compile_error()
            .into();
    }

    // define the fields to be inserted and parse into DataEnum
    let default_instantiate_fields: TokenStream = quote! {
        struct InstantiateMsg {
            pub ownable_id: String,
            pub package: String,
            pub nft: Option<NFT>,
            pub ownable_type: Option<String>,
            pub network_id: u8,
        }
    }
    .into();

    let default_ast: DeriveInput = parse_macro_input!(default_instantiate_fields);
    let default_fields = match default_ast.data {
        Struct(DataStruct { fields, .. }) => fields,
        _ => panic!("only structs can accept fields"),
    };

    let mut input_ast: DeriveInput = parse_macro_input!(input);
    let input_fields_data = match &mut input_ast.data {
        Struct(DataStruct { fields, .. }) => fields,
        _ => panic!("only structs can accept fields")
    };

    // push the default fields onto the input
    if let syn::Fields::Named(FieldsNamed { named, .. }) = input_fields_data {
        named.extend(default_fields);
    }

    quote! { #input_ast }.into()
}


