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
use syn::{ItemFn, parse_macro_input};
use types::{ArgsStruct, Attrs};

/// Takes a function as input and transforms it
/// into something that can be used as a NASL builtin function.
///
/// The input function is a normal rust function with certain restrictions
/// on the types of the arguments and the return type. The input arguments
/// need to either be within a selected set of specific, allowed types
/// (`Context`, `Register`, ...) or be of any type that
/// implements the `FromNaslValue` trait.
///
/// Conversely, the return type needs to implement the `ToNaslResult` type.
///
/// # Positional arguments
/// In order to define a NASL function that takes positional arguments, simply
/// define a normal rust function and take a number of arguments.
///
/// Example:
/// ```rust ignore
/// # use nasl_function_proc_macro::nasl_function;
/// #[nasl_function]
/// fn string_index(string: &str, index: usize) -> &str {
///     string[index].chars().nth(i).unwrap()
/// }
/// ```
///
/// Here, `string` is the first and `index` the second positional argument.
///
/// # Optional arguments
/// In order to receive optional arguments, where omitting them during the function call should not result in an error, we can simply make the function receive `Option<T>`. For example:
///
/// ```rust ignore
/// # use nasl_function_proc_macro::nasl_function;
/// #[nasl_function]
/// fn hexstr(s: Option<NaslValue>) -> Option<String> {
///     match s? {
///         NaslValue::String(s) => Some(encode_hex(s.as_bytes())),
///         NaslValue::Data(bytes) => Some(encode_hex(&bytes)),
///         _ => None,
///     }
/// }
/// ```
///
/// # Named arguments
/// In order to receive named arguments, additional attributes can be given to the `nasl_function` macro. For example:
///
/// ```rust ignore
/// # use nasl_function_proc_macro::nasl_function;
/// #[nasl_function(maybe_named(length), named(data))]
/// fn crap(length: usize, data: Option<&str>) -> String {
///     let data = data.unwrap_or("X");
///     data.repeat(length)
/// }
/// ```
///
/// In this example, `length` may be either positional or named, which is why it is of `maybe_named` type. Data may only be given as a named argument, so it is `named`. Note that `data` is of type `Option<&str>`, making it optional.
///
///
/// # Maybe arguments
/// The `Maybe` type can be used to handle the case of an argument
/// that should be of some type `T`, but for which giving a different
/// type does not result in an error. Instead, the inner `Option` of
/// the `Maybe` will simply be `None`, allowing the function author
/// to handle the wrong type gracefully.
///
/// ```rust ignore
/// # use nasl_function_proc_macro::nasl_function;
/// #[nasl_function]
/// fn data_to_hexstr(bytes: Maybe<&[u8]>) -> Option<String> {
///     bytes.map(encode_hex)
/// }
/// ```
///
/// # `Context`
/// The `Context` can be obtained in a function, simply by adding it as an argument:
/// ```rust ignore
/// # use nasl_function_proc_macro::nasl_function;
/// #[nasl_function]
/// fn foo(context: &Context, ...) -> ... {
/// }
/// ```
/// In a similar fashion, `&Register` is also an allowed parameter:
///
/// # `Positionals` and `CheckedPositionals`
/// For functions that receive lists of positional arguments, the `Positionals` and `CheckedPositionals` types are provided. `Positionals` simply provides an iterator over the arguments with item type `Result<T, FunctionErrorKind>`,  meaning that the conversion is done while iterating over the arguments:
///
/// ```rust ignore
/// # use nasl_function_proc_macro::nasl_function;
/// #[nasl_function]
/// fn foo(positional: Positionals<&NaslValue>) -> Result<(), FunctionErrorKind> {
///     for arg in positional.iter() {
///         println!("{}", arg?) // Conversion would fail here
///     }
/// }
/// ```
///
/// The `CheckedPositionals` type checks all arguments before the inner function is even called (and returns an error if one fails to convert), which is convenient but also potentially slow:
///
///
/// ```rust ignore
/// # use nasl_function_proc_macro::nasl_function;
/// #[nasl_function]
/// fn foo(positional: CheckedPositionals<&NaslValue>) {
///     for arg in positional.iter() {
///         do_something(arg)
///     }
/// }
/// ```
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
