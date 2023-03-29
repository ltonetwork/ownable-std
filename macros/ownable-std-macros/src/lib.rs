use proc_macro::TokenStream;
use quote::quote;
use syn::DataEnum;
use syn::DeriveInput;
use syn::parse_macro_input;
use syn::Data::Enum;


#[proc_macro_attribute]
pub fn ownables_std_execute_msg(metadata: TokenStream, input: TokenStream) -> TokenStream {
    // define variants to be inserted to the input enum
    let default_execute_variants = quote! {
        enum DefVariants {
            Transfer { to: Addr },
            Lock {},
        }
    };
    let default_execute_variants: DeriveInput = parse_macro_input!(default_execute_variants);
    let Enum(DataEnum {
        variants: default_variants, ..
    }) = default_execute_variants.data;

    let mut input: DeriveInput = parse_macro_input!(input);
    // input.data is either Struct, Enum, or Union. assert enum.
    let variants = match input.data {
        Enum(DataEnum { variants, ..}) => variants,
        _ => panic!("this derive macro only works on enums"),
    };

    variants.extend(default_variants.into_iter());
    
    metadata
}

// #[proc_macro_attribute]
// pub fn ownables_std_query_msg(metadata: TokenStream, input: TokenStream) -> TokenStream {
//     let default_query_variants = quote! {
//         enum DefVariants {
//             GetInfo {},
//             GetMetadata {},
//             GetWidgetState {},
//             IsLocked {},
//         }
//     };

//     input
// }
