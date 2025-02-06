use proc_macro2::{Span, TokenStream};
use quote::quote_spanned;

pub type Result<T> = std::result::Result<T, Error>;

pub struct Error {
    pub span: Span,
    pub kind: ErrorKind,
}

pub enum ErrorKind {
    TooManyAttributes,
    ArgInAttrDoesNotExist,
    OnlyNormalArgumentsAllowed,
    WrongArgumentOrder,
    MovedReceiverType,
    TypedRefReceiverType,
}

impl Error {
    pub fn emit(&self) -> TokenStream {
        let message = format!("Error in nasl_function: {}", self.message());
        quote_spanned! {
            self.span =>
            compile_error!(#message);
        }
    }

    pub fn message(&self) -> String {
        match self.kind {
            ErrorKind::OnlyNormalArgumentsAllowed => {
                "Only normal identifier arguments are allowed on the function."
            }
            ErrorKind::TooManyAttributes => {
                "Argument is named more than once in attributes."
            }
            ErrorKind::ArgInAttrDoesNotExist => {
                "Argument mentioned in attribute does not exist in function signature."
            }
            ErrorKind::MovedReceiverType => {
                "Receiver argument is of type `self`. Currently, only `&self` receiver types are supported."
            }
            ErrorKind::TypedRefReceiverType => {
                "Specific type specified in receiver argument. Currently, only `&self` is supported."
            }
            ErrorKind::WrongArgumentOrder => {
                "Argument in wrong position. Order of arguments should be: Context/Register, Positionals, Named, *Positional list"
            }
        }.into()
    }
}
