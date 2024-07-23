mod error;
mod utils;

use std::collections::HashSet;

use error::{Error, ErrorKind, Result};
use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    parenthesized, parse::Parse, parse_macro_input, punctuated::Punctuated, spanned::Spanned,
    FnArg, Ident, ItemFn, Signature, Token, Type,
};
use utils::{get_subty_if_name_is, ty_is_context, ty_name_is};

#[proc_macro_attribute]
pub fn nasl_function(
    attrs: proc_macro::TokenStream,
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let function = parse_macro_input!(input as syn::ItemFn);
    let attrs = parse_macro_input!(attrs as Attrs);
    nasl_function_internal(function, attrs)
        .unwrap_or_else(|e| e.emit().into())
        .into()
}

fn nasl_function_internal(function: ItemFn, attrs: Attrs) -> Result<TokenStream> {
    let args = ArgsStruct::try_parse(&function, &attrs)?;
    attrs.verify()?;
    Ok(args.impl_nasl_function_args())
}

mod attrs {
    syn::custom_keyword!(named);
    syn::custom_keyword!(maybe_named);
}

struct Attr {
    kind: AttrKind,
    ident: Ident,
}

enum AttrKind {
    Named,
    MaybeNamed,
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
        Ok(Self {
            kind,
            ident: content.parse()?,
        })
    }
}

struct Attrs {
    attrs: Vec<Attr>,
}

impl Attrs {
    fn get_arg_kind(&self, ident: &Ident, position: usize, ty: &Type) -> ArgKind {
        if ty_is_context(ty) {
            return ArgKind::Context;
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
            .find(|attr| &attr.ident == ident)
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

    fn verify(&self) -> Result<()> {
        let ids: HashSet<_> = self.attrs.iter().map(|attr| &attr.ident).collect();
        if ids.len() != self.attrs.iter().count() {
            Err(Error {
                // TODO: Fix the span here
                span: self.attrs[0].ident.span(),
                kind: ErrorKind::TooManyAttributes,
            })
        } else {
            Ok(())
        }
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

struct ArgsStruct<'a> {
    function: &'a ItemFn,
    args: Vec<Arg<'a>>,
    receiver_type: ReceiverType,
}

enum ReceiverType {
    None,
    RefSelf,
}

struct Arg<'a> {
    ident: &'a Ident,
    ty: &'a Type,
    optional: bool,
    kind: ArgKind,
    mutable: bool,
}

enum ArgKind {
    Positional(PositionalArg),
    Named(NamedArg),
    MaybeNamed(PositionalArg, NamedArg),
    Context,
    PositionalIterator,
    CheckedPositionalIterator,
}

struct NamedArg {
    name: String,
}

struct PositionalArg {
    position: usize,
}

impl<'a> Arg<'a> {
    fn new(arg: &'a FnArg, attrs: &Attrs, position: usize) -> Result<Self> {
        let (ident, ty, mutable, optional) = get_arg_info(arg)?;
        let kind = attrs.get_arg_kind(ident, position, ty);
        Ok(Self {
            kind,
            ident,
            ty,
            optional,
            mutable,
        })
    }
}

fn get_arg_info(arg: &FnArg) -> Result<(&Ident, &Type, bool, bool)> {
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
            let (optional, ty) = if let Some(ty) = get_subty_if_name_is(ty, "Option") {
                (true, ty)
            } else {
                (false, ty.as_ref())
            };
            Ok((ident, ty, mutable, optional))
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
    let receiver_type = if function.sig.inputs.iter().any(is_self_arg) {
        ReceiverType::RefSelf
    } else {
        ReceiverType::None
    };
    Ok((args, receiver_type))
}

impl<'a> ArgsStruct<'a> {
    fn try_parse(function: &'a ItemFn, attrs: &'a Attrs) -> Result<Self> {
        let (args, receiver_type) = parse_function_args(function, attrs)?;
        Ok(Self {
            function: function,
            args,
            receiver_type,
        })
    }

    fn positional(&self) -> impl Iterator<Item = (&Arg<'a>, &PositionalArg)> + '_ {
        self.args.iter().filter_map(|arg| match arg.kind {
            ArgKind::Positional(ref positional) => Some((arg, positional)),
            _ => None,
        })
    }

    fn num_required_positional(&self) -> usize {
        self.positional().filter(|(arg, _)| !arg.optional).count()
    }

    fn impl_nasl_function_args(&self) -> TokenStream {
        let ItemFn {
            attrs,
            vis,
            sig,
            block,
        } = self.function;
        let stmts = &block.stmts;
        let args = self.get_args();
        let Signature {
            fn_token,
            ident,
            generics,
            output,
            ..
        } = sig;
        let self_arg = match self.receiver_type {
            ReceiverType::None => quote! {},
            ReceiverType::RefSelf => quote! {&self,},
        };
        let inputs = quote! {
            #self_arg
            _register: &::nasl_builtin_utils::Register,
            _context: &::nasl_builtin_utils::Context,
        };
        let output_ty = match output {
            syn::ReturnType::Default => quote! { () },
            syn::ReturnType::Type(_, ty) => quote! { #ty },
        };
        // We annotate the _inner closure with the output_ty to aid
        // the compiler with type inference.
        quote! {
            #(#attrs)* #vis #fn_token #ident #generics ( #inputs ) -> ::nasl_builtin_utils::NaslResult {
                #args
                let _inner = || -> #output_ty {
                    #(#stmts)*
                };
                <#output_ty as ::nasl_builtin_utils::function::ToNaslResult>::to_nasl_result(_inner())
            }
        }
    }

    fn get_args(&self) -> TokenStream {
        self
            .args.iter().map(|arg| {
                let num_required_positional_args = self.num_required_positional();
                let ident = &arg.ident;
                let mutability = if arg.mutable { quote! { mut } } else { quote ! {}};
                let ty = &arg.ty;
                let parse = match &arg.kind {
                    ArgKind::Positional(positional) => {
                        let position = positional.position;
                            if arg.optional {
                                quote! { ::nasl_builtin_utils::function::utils::get_optional_positional_arg::<#ty>(_register, #position)? }
                            }
                            else {
                                quote! { ::nasl_builtin_utils::function::utils::get_positional_arg::<#ty>(_register, #position, #num_required_positional_args)? }
                            }
                    }
                    ArgKind::Named(named) => {
                        let name = &named.name;
                        if arg.optional {
                            quote! { ::nasl_builtin_utils::function::utils::get_optional_named_arg::<#ty>(_register, #name)? }
                        }
                        else {
                            quote! { ::nasl_builtin_utils::function::utils::get_named_arg::<#ty>(_register, #name)? }
                        }
                    }
                    ArgKind::MaybeNamed(positional, named) => {
                        let name = &named.name;
                        let position = positional.position;
                        if arg.optional {
                            quote! {
                                ::nasl_builtin_utils::function::utils::get_optional_maybe_named_arg::<#ty>(_register, #name, #position)?
                            }
                        }
                        else {
                            quote! {
                                ::nasl_builtin_utils::function::utils::get_maybe_named_arg::<#ty>(_register, #name, #position)?
                            }
                        }
                    }
                    ArgKind::Context => {
                        quote! {
                            _context
                        }
                    },
                    ArgKind::PositionalIterator => {
                        quote! {
                            ::nasl_builtin_utils::function::Positionals::new(_register)
                        }
                    }
                    ArgKind::CheckedPositionalIterator => {
                        quote! {
                            ::nasl_builtin_utils::function::CheckedPositionals::new(_register)?
                        }
                    }
                };
                quote! {
                    let #mutability #ident = #parse;
                }
            })
            .collect()
    }
}
