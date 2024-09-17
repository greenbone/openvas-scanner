mod codegen;
mod error;
mod parse;
mod types;
mod utils;

use error::Result;
use proc_macro2::TokenStream;
use syn::{parse_macro_input, ItemFn};
use types::{ArgsStruct, Attrs};

#[proc_macro_attribute]
pub fn nasl_function(
    attrs: proc_macro::TokenStream,
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let function = parse_macro_input!(input as syn::ItemFn);
    let attrs = parse_macro_input!(attrs as Attrs);
    nasl_function_internal(function, attrs)
        .unwrap_or_else(|e| e.emit())
        .into()
}

fn nasl_function_internal(function: ItemFn, attrs: Attrs) -> Result<TokenStream> {
    let args = ArgsStruct::try_parse(&function, &attrs)?;
    Ok(args.impl_nasl_function_args())
}
