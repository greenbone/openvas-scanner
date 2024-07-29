use crate::types::*;
use proc_macro2::TokenStream;
use quote::quote;
use syn::{ItemFn, Signature};

impl<'a> ArgsStruct<'a> {
    fn positional(&self) -> impl Iterator<Item = (&Arg<'a>, &PositionalArg)> + '_ {
        self.args.iter().filter_map(|arg| match arg.kind {
            ArgKind::Positional(ref positional) => Some((arg, positional)),
            _ => None,
        })
    }

    fn num_required_positional(&self) -> usize {
        self.positional().filter(|(arg, _)| !arg.optional).count()
    }

    fn max_num_allowed_positional(&self) -> usize {
        self.args
            .iter()
            .filter(|arg| matches!(arg.kind, ArgKind::Positional(_) | ArgKind::MaybeNamed(_, _)))
            .count()
    }

    fn has_positional_iterator_arg(&self) -> bool {
        self.args.iter().any(|arg| {
            matches!(
                arg.kind,
                ArgKind::PositionalIterator | ArgKind::CheckedPositionalIterator
            )
        })
    }

    fn get_args(&self) -> TokenStream {
        self
            .args.iter().map(|arg| {
                let num_required_positional_args = self.num_required_positional();
                let ident = &arg.ident;
                let mutability = if arg.mutable { quote! { mut } } else { quote ! {}};
                let inner_ty = &arg.inner_ty;
                let ty = &arg.ty;
                let expr = match &arg.kind {
                    ArgKind::Positional(positional) => {
                        let position = positional.position;
                            if arg.optional {
                                quote! { ::nasl_builtin_utils::function::utils::get_optional_positional_arg::<#inner_ty>(_register, #position)? }
                            }
                            else {
                                quote! { ::nasl_builtin_utils::function::utils::get_positional_arg::<#inner_ty>(_register, #position, #num_required_positional_args)? }
                            }
                    }
                    ArgKind::Named(named) => {
                        let name = &named.name;
                        if arg.optional {
                            quote! { ::nasl_builtin_utils::function::utils::get_optional_named_arg::<#inner_ty>(_register, #name)? }
                        }
                        else {
                            quote! { ::nasl_builtin_utils::function::utils::get_named_arg::<#inner_ty>(_register, #name)? }
                        }
                    }
                    ArgKind::MaybeNamed(positional, named) => {
                        let name = &named.name;
                        let position = positional.position;
                        if arg.optional {
                            quote! {
                                ::nasl_builtin_utils::function::utils::get_optional_maybe_named_arg::<#inner_ty>(_register, #name, #position)?
                            }
                        }
                        else {
                            quote! {
                                ::nasl_builtin_utils::function::utils::get_maybe_named_arg::<#inner_ty>(_register, #name, #position)?
                            }
                        }
                    }
                    ArgKind::Context => {
                        quote! {
                            _context
                        }
                    },
                    ArgKind::Register => {
                        quote! {
                            _register
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
                    let #mutability #ident: #ty = #expr;
                }
            })
            .collect()
    }

    fn make_array_of_names(&self, f: impl Fn(&ArgKind) -> Option<&str>) -> TokenStream {
        let contents: TokenStream = self
            .args
            .iter()
            .filter_map(|arg| f(&arg.kind))
            .map(|name| {
                quote! { #name, }
            })
            .collect();
        quote! { &[#contents] }
    }

    fn gen_checks(&self) -> TokenStream {
        let named_array = self.make_array_of_names(ArgKind::get_named_arg_name);
        let maybe_named_array = self.make_array_of_names(ArgKind::get_maybe_named_arg_name);
        let num_allowed_positional_args = if self.has_positional_iterator_arg() {
            quote! { None }
        } else {
            let num = self.max_num_allowed_positional();
            quote! { Some(#num) }
        };
        let fn_name = self.function.sig.ident.to_string();
        quote! {
            ::nasl_builtin_utils::function::utils::check_args(_register, #fn_name, #named_array, #maybe_named_array, #num_allowed_positional_args)?;
        }
    }

    pub fn impl_nasl_function_args(&self) -> TokenStream {
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
        let checks = self.gen_checks();
        // We annotate the _inner closure with the output_ty to aid
        // the compiler with type inference.
        quote! {
            #(#attrs)* #vis #fn_token #ident #generics ( #inputs ) -> ::nasl_builtin_utils::NaslResult {
                #checks
                #args
                let _inner = || -> #output_ty {
                    #(#stmts)*
                };
                <#output_ty as ::nasl_builtin_utils::function::ToNaslResult>::to_nasl_result(_inner())
            }
        }
    }
}
