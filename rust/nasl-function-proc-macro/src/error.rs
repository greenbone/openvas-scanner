use proc_macro2::{Span, TokenStream};
use quote::quote_spanned;

pub type Result<T> = std::result::Result<T, Error>;

pub struct Error {
    pub span: Span,
    pub kind: ErrorKind,
}

#[allow(unused)]
pub enum ErrorKind {
    NotAStruct,
    ForbiddenGenerics,
    TooManyAttributes,
}

impl Error {
    pub fn emit(&self) -> TokenStream {
        let message = format!(
            "Error while deriving trait NaslFunctionArg: {}",
            self.message()
        );
        quote_spanned! {
            self.span =>
            compile_error!(#message);
        }
    }

    pub fn message(&self) -> String {
        match self.kind {
            ErrorKind::NotAStruct => "trait NaslFunctionArg can only be derived on structs.".into(),
            ErrorKind::ForbiddenGenerics => {
                "Struct can only have a single lifetime or none at all.".into()
            }
            ErrorKind::TooManyAttributes => "Field has more than one attribute.".into(),
        }
    }
}
