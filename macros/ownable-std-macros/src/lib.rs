use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, AttributeArgs, Data::Enum, DataEnum, DeriveInput};

#[proc_macro_attribute]
pub fn ownables_std_execute_msg(metadata: TokenStream, input: TokenStream) -> TokenStream {
   
    // validate no input args
    let args = parse_macro_input!(metadata as AttributeArgs);
    if let Some(arg) = args.first() {
        return syn::Error::new_spanned(arg, "no args expected")
            .to_compile_error()
            .into();
    }

    // define the variants to be inserted and parse into DataEnum
    let default_execute_variants: TokenStream = quote! {
        enum ExecuteMsg { 
            Transfer {to: Addr},
            Lock {},
        }
    }
    .into();
    let default_variants_input: DeriveInput = parse_macro_input!(default_execute_variants);
    let default_variants = match default_variants_input.data {
        Enum(DataEnum { variants, .. }) => variants,
        _ => panic!("only enums can provide variants"),
    };

    // parse the input variants
    let mut input_variants: DeriveInput = parse_macro_input!(input);
    let input_variants_data = match &mut input_variants.data {
        Enum(DataEnum { variants, .. }) => variants,
        _ => panic!("only enums can accept variants")
    };

    // insert variants from the right to the left
    input_variants_data.extend(default_variants.into_iter());

    quote! { #input_variants }.into()
}
