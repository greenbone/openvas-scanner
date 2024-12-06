//! This crate provides the `nasl_function` proc macro, which is
//! designed to make implementing new NASL builtin functions as
//! convenient as possible.
//!
//! Design: There are two main purposes that the `nasl_function` macro
//! serves.
//!
//! Purpose 1: Unify argument handling.
//!
//! The `nasl_function!` macro provides a structured approach to argument handling
//! within NASL builtin functions. The macro takes as input a function
//! taking any number of arguments, along with instructions on whether
//! those arguments are named, positional, optional, etc. It then
//! produces a function that automatically handles conversion of the
//! arguments into the correct types and produces consistent error
//! messages if the function has been called with an invalid set of
//! arguments.
//!
//! To do so, the macro transforms the annotated function into a function
//! taking `&Context` and `&Register` as arguments (plus self arguments
//! if needed) and then calls the original function from within the transformed
//! function, deriving each argument from the `FromNaslValue` implementation
//! of its type and handling optional and named arguments appropriately.
//!
//! The macro renames the inner function into a proper, first class
//! function instead of a closure in order to provide support for
//! async functions (without relying on the unstable async
//! closures).
//!
//! Purpose 2: Provide a uniform way to add builtin functions to function sets.
//!
//! NASL builtin functions come in one of several types, depending on
//! their asyncness and whether they are stateless or stateful (and
//! whether they require mutable access to their state, if they
//! are). The `NaslFunction` type defined in the executor code is a
//! singular type which can represent all the various variants of
//! builtin functions.  The executor also provides the
//! `StoredFunctionSet`, which represents a set of `NaslFunction`s
//! together with their state. This state struct is used both as the
//! actual state that these functions require, as well as an
//! identifying name.  Together, the `NaslFunction` and
//! `StoredFunctionSet` types provide the ability to store NASL
//! functions in a type-erased way, so that the interpreter can run
//! them independently of their properties.
//!
//! In order to provide a unified interface for adding NASL functions
//! to `StoredFunctionSet`s, there needs to be a way to convert any of
//! the 6 variants which builtin functions come in (sync_stateless,
//! async_stateless, sync_stateful, ... ) into their corresponding
//! variant of `NaslFunction`. On the surface, this problem sounds
//! simple: Simply implement `Into<NaslFunction>` for `Fn(&Context,
//! &Register) -> NaslResult` as well as for `Fn(&Context, &Register)
//! -> Future<NaslResult>`, as well as for the other 4 variants. Then
//! provide a `add_function` method on `StoredFunctionSet` that takes
//! any `impl Into<NaslFunction>` as argument. The problem with this
//! approach is that the Rust compiler cannot determine that these 6
//! implementations are coherent, i.e. it believes that there might be
//! a type `T` that implements multiple of these `Fn` traits
//! simultaneously, which would result in overlapping trait impls.
//!
//! In order to solve this problem, the `nasl_function!` macro
//! transforms the annotated function into a special function that
//! takes a `StoredFunctionSet` and adds the correct variant of
//! `NaslFunction` to the set. This is a very indirect approach, but
//! it works because the `nasl_function!` macro knows exactly what the
//! signature of the annotated function is and can therefore derive
//! which of the 6 variants of `NaslFunction` it should become,
//! without requiring type-erasure via an intermediate trait.

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
