use crate::types::*;
use proc_macro2::TokenStream;
use quote::quote;
use syn::{token::Async, Ident, ItemFn, Signature};

impl<'a> ArgsStruct<'a> {
    fn positional(&self) -> impl Iterator<Item = (&Arg<'a>, &PositionalArg)> + '_ {
        self.args.iter().filter_map(|arg| match arg.kind {
            ArgKind::Positional(ref positional) => Some((arg, positional)),
            _ => None,
        })
    }

    fn num_required_positional(&self) -> usize {
        self.positional()
            .filter(|(arg, _)| arg.is_required_positional())
            .count()
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
                                quote! { crate::nasl::utils::function::utils::get_optional_positional_arg::<#inner_ty>(_register, #position)? }
                            }
                            else {
                                quote! { crate::nasl::utils::function::utils::get_positional_arg::<#inner_ty>(_register, #position, #num_required_positional_args)? }
                            }
                    }
                    ArgKind::Named(named) => {
                        let name = &named.name;
                        if arg.optional {
                            quote! { crate::nasl::utils::function::utils::get_optional_named_arg::<#inner_ty>(_register, #name)? }
                        }
                        else {
                            quote! { crate::nasl::utils::function::utils::get_named_arg::<#inner_ty>(_register, #name)? }
                        }
                    }
                    ArgKind::MaybeNamed(positional, named) => {
                        let name = &named.name;
                        let position = positional.position;
                        if arg.optional {
                            quote! {
                                crate::nasl::utils::function::utils::get_optional_maybe_named_arg::<#inner_ty>(_register, #name, #position)?
                            }
                        }
                        else {
                            quote! {
                                crate::nasl::utils::function::utils::get_maybe_named_arg::<#inner_ty>(_register, #name, #position)?
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
                            crate::nasl::utils::function::Positionals::new(_register)
                        }
                    }
                    ArgKind::CheckedPositionalIterator => {
                        quote! {
                            crate::nasl::utils::function::CheckedPositionals::new(_register)?
                        }
                    }
                };
                quote! {
                    let #mutability #ident: #ty = #expr;
                }
            })
            .collect()
    }

    fn get_fn_args_names(&self) -> TokenStream {
        self.args
            .iter()
            .map(|arg| {
                let ident = &arg.ident;
                quote! { #ident, }
            })
            .collect()
    }

    pub fn get_inner_call_expr(
        &self,
        mangled_ident: &Ident,
        asyncness: Option<Async>,
    ) -> TokenStream {
        let fn_args_names = self.get_fn_args_names();
        let call_expr = match self.receiver_type {
            ReceiverType::None => quote! { #mangled_ident(#fn_args_names) },
            ReceiverType::RefSelf => quote! { self.#mangled_ident(#fn_args_names) },
        };
        let await_ = match asyncness {
            Some(_) => quote! { .await },
            None => quote! {},
        };
        quote! { #call_expr #await_; }
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
            crate::nasl::utils::function::utils::check_args(_register, #fn_name, #named_array, #maybe_named_array, #num_allowed_positional_args)?;
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
        let get_args = self.get_args();
        let fn_args = &sig.inputs;
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
            _register: &crate::nasl::Register,
            _context: &crate::nasl::Context<'_>,
        };
        let output_ty = match output {
            syn::ReturnType::Default => quote! { () },
            syn::ReturnType::Type(_, ty) => quote! { #ty },
        };
        let asyncness = sig.asyncness;
        let checks = self.gen_checks();
        let mangled_name = format!("_internal_{}", ident);
        let mangled_ident = Ident::new(&mangled_name, ident.span());
        let inner_call = self.get_inner_call_expr(&mangled_ident, asyncness);
        quote! {
            #asyncness fn #mangled_ident #generics ( #fn_args ) -> #output_ty {
                #(#stmts)*
            }

            #(#attrs)* #vis #asyncness #fn_token #ident #generics ( #inputs ) -> crate::nasl::NaslResult {
                #checks
                #get_args
                let _result = #inner_call;
                <#output_ty as crate::nasl::ToNaslResult>::to_nasl_result(_result)
            }
        }
    }
}
