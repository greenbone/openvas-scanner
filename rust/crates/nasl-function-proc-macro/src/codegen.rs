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
                ArgKind::PositionalIterator(_) | ArgKind::CheckedPositionalIterator(_)
            )
        })
    }

    fn has_register_arg(&self) -> bool {
        self.args
            .iter()
            .any(|arg| matches!(arg.kind, ArgKind::Register))
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
                    ArgKind::PositionalIterator(arg) => {
                        let position = arg.position;
                        quote! {
                            crate::nasl::utils::function::Positionals::new(_register, #position)
                        }
                    }
                    ArgKind::CheckedPositionalIterator(arg) => {
                        let position = arg.position;
                        quote! {
                            crate::nasl::utils::function::CheckedPositionals::new(_register, #position)?
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
            ReceiverType::RefSelf | ReceiverType::RefMutSelf => {
                quote! { self.#mangled_ident(#fn_args_names) }
            }
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
        if self.has_register_arg() {
            return quote! {};
        }
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

    fn impl_add_to_set(
        &self,
        ident: &Ident,
        fn_name: &Ident,
        asyncness: Option<Async>,
    ) -> TokenStream {
        let nasl_function_expr = match (asyncness, &self.receiver_type) {
            (Some(_), ReceiverType::None) => {
                quote! { AsyncStateless(Box::new(#fn_name)) }
            }
            (Some(_), ReceiverType::RefSelf) => {
                quote! { AsyncStateful(Box::new(Self::#fn_name)) }
            }
            (Some(_), ReceiverType::RefMutSelf) => {
                quote! { AsyncStatefulMut(Box::new(Self::#fn_name)) }
            }
            (None, ReceiverType::None) => quote! { SyncStateless(#fn_name) },
            (None, ReceiverType::RefSelf) => {
                quote! { SyncStateful(Self::#fn_name) }
            }
            (None, ReceiverType::RefMutSelf) => {
                quote! { SyncStatefulMut(Self::#fn_name) }
            }
        };

        let (generics, state_type) = match &self.receiver_type {
            ReceiverType::None => (quote! { < S > }, quote! { S }),
            ReceiverType::RefSelf | ReceiverType::RefMutSelf => (quote! {}, quote! { Self }),
        };

        quote! {
            fn #ident #generics (set: &mut crate::nasl::utils::StoredFunctionSet<#state_type>, name: &str) {
                set.add_nasl_function(name, crate::nasl::utils::NaslFunction::#nasl_function_expr);
            }
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
            ReceiverType::RefMutSelf => quote! {&mut self,},
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
        let mangled_ident_original_fn = Ident::new(&format!("_internal_{}", ident), ident.span());
        let mangled_ident_transformed_fn =
            Ident::new(&(format!("_internal_convert_{}", ident)), ident.span());
        let inner_call = self.get_inner_call_expr(&mangled_ident_original_fn, asyncness);
        let add_to_set = self.impl_add_to_set(ident, &mangled_ident_transformed_fn, asyncness);

        quote! {
            #[allow(clippy::too_many_arguments)]
            #asyncness fn #mangled_ident_original_fn #generics ( #fn_args ) -> #output_ty {
                #(#stmts)*
            }

            #(#attrs)* #vis #asyncness #fn_token #mangled_ident_transformed_fn #generics ( #inputs ) -> crate::nasl::NaslResult {
                #checks
                #get_args
                let _result = #inner_call;
                <#output_ty as crate::nasl::ToNaslResult>::to_nasl_result(_result)
            }

            #add_to_set
        }
    }
}
