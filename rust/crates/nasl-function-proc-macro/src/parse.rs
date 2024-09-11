use std::collections::HashSet;

use crate::error::{Error, ErrorKind, Result};
use crate::types::*;
use crate::utils::{get_subty_if_name_is, ty_is_context, ty_is_register, ty_name_is};
use syn::punctuated::Punctuated;
use syn::token::Comma;
use syn::{parenthesized, parse::Parse, spanned::Spanned, FnArg, Ident, ItemFn, Token, Type};

mod attrs {
    syn::custom_keyword!(named);
    syn::custom_keyword!(maybe_named);
}

impl Parse for Attr {
    fn parse(stream: syn::parse::ParseStream) -> syn::Result<Self> {
        let lookahead = stream.lookahead1();
        let kind = if lookahead.peek(attrs::named) {
            let _: attrs::named = stream.parse()?;
            Ok(AttrKind::Named)
        } else if lookahead.peek(attrs::maybe_named) {
            let _: attrs::maybe_named = stream.parse()?;
            Ok(AttrKind::MaybeNamed)
        } else {
            Err(lookahead.error())
        }?;
        let content;
        let _ = parenthesized!(content in stream);
        let idents: Punctuated<Ident, Token![,]> =
            content.parse_terminated(Ident::parse, Token![,])?;
        Ok(Self {
            kind,
            idents: idents.into_iter().collect(),
        })
    }
}

impl Attrs {
    fn get_arg_kind(&self, ident: &Ident, position: usize, ty: &Type) -> ArgKind {
        if ty_is_context(ty) {
            return ArgKind::Context;
        }
        if ty_is_register(ty) {
            return ArgKind::Register;
        }
        if ty_name_is(ty, "Positionals") {
            return ArgKind::PositionalIterator;
        }
        if ty_name_is(ty, "CheckedPositionals") {
            return ArgKind::CheckedPositionalIterator;
        }
        let attr_kind = self
            .attrs
            .iter()
            .find(|attr| attr.idents.contains(ident))
            .map(|attr| &attr.kind);
        let make_named = || NamedArg {
            name: ident.to_string(),
        };
        let make_positional = || PositionalArg { position };
        match attr_kind {
            None => ArgKind::Positional(make_positional()),
            Some(AttrKind::Named) => ArgKind::Named(make_named()),
            Some(AttrKind::MaybeNamed) => ArgKind::MaybeNamed(make_positional(), make_named()),
        }
    }

    pub fn verify(&self) -> Result<()> {
        let mut ids: HashSet<_> = HashSet::default();
        for attr in self.attrs.iter() {
            for ident in attr.idents.iter() {
                if !ids.insert(ident) {
                    return Err(Error {
                        span: ident.span(),
                        kind: ErrorKind::TooManyAttributes,
                    });
                }
            }
        }
        Ok(())
    }
}

impl Parse for Attrs {
    fn parse(stream: syn::parse::ParseStream) -> syn::Result<Self> {
        let attrs: Punctuated<Attr, Token![,]> = stream.parse_terminated(Attr::parse, Token![,])?;
        Ok(Self {
            attrs: attrs.into_iter().collect(),
        })
    }
}

impl<'a> Arg<'a> {
    fn new(arg: &'a FnArg, attrs: &Attrs, position: usize) -> Result<Self> {
        let (ident, ty, inner_ty, mutable, optional) = get_arg_info(arg)?;
        let kind = attrs.get_arg_kind(ident, position, ty);
        Ok(Self {
            kind,
            ident,
            ty,
            inner_ty,
            optional,
            mutable,
        })
    }
}

impl ReceiverType {
    pub fn new(inputs: &Punctuated<FnArg, Comma>) -> Result<Self> {
        let first_input = inputs.iter().next();
        if let Some(first_input) = first_input {
            let make_err = |kind| {
                Err(Error {
                    kind,
                    span: first_input.span(),
                })
            };
            Ok(match first_input {
                FnArg::Receiver(rec) => {
                    // `self`
                    if rec.reference.is_none() {
                        return make_err(ErrorKind::MovedReceiverType);
                    }
                    // e.g. `self: Box<Self>`
                    else if rec.colon_token.is_some() {
                        return make_err(ErrorKind::TypedRefReceiverType);
                    }
                    // `&mut self`
                    else if rec.mutability.is_some() {
                        ReceiverType::RefMutSelf
                    } else {
                        ReceiverType::RefSelf
                    }
                }
                FnArg::Typed(_) => ReceiverType::None,
            })
        } else {
            Ok(ReceiverType::None)
        }
    }
}

fn get_arg_info(arg: &FnArg) -> Result<(&Ident, &Type, &Type, bool, bool)> {
    match arg {
        FnArg::Receiver(_) => unreachable!(),
        FnArg::Typed(typed) => {
            let (ident, mutable) = match typed.pat.as_ref() {
                syn::Pat::Ident(ident) => (&ident.ident, ident.mutability.is_some()),
                _ => {
                    return Err(Error {
                        span: typed.pat.span(),
                        kind: ErrorKind::OnlyNormalArgumentsAllowed,
                    })
                }
            };
            let ty = &typed.ty;
            let (optional, inner_ty) = if let Some(ty) = get_subty_if_name_is(ty, "Option") {
                (true, ty)
            } else {
                (false, ty.as_ref())
            };
            Ok((ident, ty, inner_ty, mutable, optional))
        }
    }
}

fn is_self_arg(arg: &FnArg) -> bool {
    matches!(arg, FnArg::Receiver(_))
}

fn parse_function_args<'a>(
    function: &'a ItemFn,
    attrs: &Attrs,
) -> Result<(Vec<Arg<'a>>, ReceiverType)> {
    let args = function
        .sig
        .inputs
        .iter()
        .filter(|arg| !is_self_arg(arg))
        .enumerate()
        .map(|(position, arg)| Arg::new(arg, attrs, position))
        .collect::<Result<Vec<_>>>()?;
    let receiver_type = ReceiverType::new(&function.sig.inputs)?;
    Ok((args, receiver_type))
}

impl<'a> ArgsStruct<'a> {
    pub fn try_parse(function: &'a ItemFn, attrs: &'a Attrs) -> Result<Self> {
        let (args, receiver_type) = parse_function_args(function, attrs)?;
        Ok(Self {
            function,
            args,
            receiver_type,
        })
    }
}
