// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! This module contains the `Executor` type, as well as utility functions and macros
//! to conveniently build sets of functions for a particular purpose.
//!
//! There are two orthogonal properties of NASL functions:
//! 1. Asyncness: Whether the function is async or not.
//! 2. Statefulness: Whether the function needs state (such as SSH connections)
//!    to work, or not. From a code perspective, these are differentiated by whether
//!    the functions take two arguments (`Context` and `Register`), which makes them stateless,
//!    or three arguments (some `State`, `Context` and `Register`), which makes them stateful.
//!    Typically, stateful functions are implemented as methods on the state struct.
//!    Stateful functions come in two flavors that differ in whether they take `&mut State` or
//!    `&State` as the first argument.
//!
//! In order to create new sets of NASL functions, the `function_set!` macro is provided.
mod nasl_function;

use std::collections::HashMap;

use async_trait::async_trait;
pub use nasl_function::NaslFunction;
use nasl_function::{AsyncDoubleArgFn, AsyncTripleArgFn};
use tokio::sync::RwLock;

use crate::nasl::prelude::*;

#[derive(Default)]
/// The executor. This is the main outward facing type of this module
/// and fulfills two main roles:
/// 1. Keeping track of all the registered, builtin NASL functions.
/// 2. Storing the required state to call those functions, if necessary. This
///    includes things such as open SSH or HTTP connections, mutexes, etc.
pub struct Executor {
    sets: Vec<Box<dyn FunctionSet + Send + Sync>>,
}

impl Executor {
    /// Construct an executor for a single function set.
    pub fn single<S: IntoFunctionSet + 'static>(s: S) -> Self
    where
        <S as IntoFunctionSet>::State: Send + Sync,
    {
        let mut exec = Self::default();
        exec.add_set(s);
        exec
    }

    pub fn add_set<S: IntoFunctionSet + 'static>(&mut self, s: S) -> &mut Self
    where
        <S as IntoFunctionSet>::State: Send + Sync,
    {
        self.sets.push(Box::new(S::into_function_set(s)));
        self
    }

    pub async fn exec(
        &self,
        k: &str,
        context: &Context<'_>,
        register: &Register,
    ) -> Option<NaslResult> {
        for set in self.sets.iter() {
            if set.contains(k) {
                return Some(set.exec(k, register, context).await);
            }
        }
        None
    }

    pub fn contains(&self, k: &str) -> bool {
        self.sets.iter().any(|set| set.contains(k))
    }
}

pub struct StoredFunctionSet<State> {
    state: RwLock<State>,
    fns: HashMap<String, NaslFunction<State>>,
}

impl<State> StoredFunctionSet<State> {
    pub fn new(state: State) -> Self {
        Self {
            state: RwLock::new(state),
            fns: HashMap::new(),
        }
    }

    pub fn async_stateful<F>(&mut self, k: &str, v: F)
    where
        F: for<'a> AsyncTripleArgFn<&'a State, &'a Register, &'a Context<'a>, Output = NaslResult>
            + Send
            + Sync
            + 'static,
    {
        self.fns
            .insert(k.to_string(), NaslFunction::AsyncStateful(Box::new(v)));
    }

    pub fn sync_stateful(&mut self, k: &str, v: fn(&State, &Register, &Context) -> NaslResult) {
        self.fns
            .insert(k.to_string(), NaslFunction::SyncStateful(v));
    }

    pub fn async_stateful_mut<F>(&mut self, k: &str, v: F)
    where
        F: for<'a> AsyncTripleArgFn<
                &'a mut State,
                &'a Register,
                &'a Context<'a>,
                Output = NaslResult,
            > + Send
            + Sync
            + 'static,
    {
        self.fns
            .insert(k.to_string(), NaslFunction::AsyncStatefulMut(Box::new(v)));
    }

    pub fn sync_stateful_mut(
        &mut self,
        k: &str,
        v: fn(&mut State, &Register, &Context) -> NaslResult,
    ) {
        self.fns
            .insert(k.to_string(), NaslFunction::SyncStatefulMut(v));
    }

    pub fn async_stateless<F>(&mut self, k: &str, v: F)
    where
        F: for<'a> AsyncDoubleArgFn<&'a Register, &'a Context<'a>, Output = NaslResult>
            + Send
            + Sync
            + 'static,
    {
        self.fns
            .insert(k.to_string(), NaslFunction::AsyncStateless(Box::new(v)));
    }

    pub fn sync_stateless(&mut self, k: &str, v: fn(&Register, &Context) -> NaslResult) {
        self.fns
            .insert(k.to_string(), NaslFunction::SyncStateless(v));
    }

    pub fn add_nasl_function(&mut self, k: &str, f: NaslFunction<State>) {
        self.fns.insert(k.to_string(), f);
    }

    /// Add a set of functions to this set.  This is useful in order
    /// to combine multiple smaller sets into one large set which can
    /// then be exported.
    /// This only works for sets with stateless functions.
    pub fn add_set<State2>(&mut self, other: impl IntoFunctionSet<State = State2>) {
        let set = other.into_function_set();
        self.fns.extend(set.fns.into_iter().map(|(name, f)| {
            let f: NaslFunction<State> = match f {
                // The following is marked as `unimplemented()` because
                // calling .add_set for a set with true stateful functions
                // 1. does not make sense (who would store the state of the inner set?)
                // 2. does not work (async closures are not stabilized yet).
                // I'd love to make this a compiler error instead, but
                // the only way I found to do so would significantly
                // remove the ergonomics of the `function_set!` macro.
                NaslFunction::AsyncStateful(_) => unimplemented!(),
                NaslFunction::SyncStateful(_) => unimplemented!(),
                NaslFunction::AsyncStatefulMut(_) => unimplemented!(),
                NaslFunction::SyncStatefulMut(_) => unimplemented!(),
                NaslFunction::AsyncStateless(f) => NaslFunction::AsyncStateless(f),
                NaslFunction::SyncStateless(f) => NaslFunction::SyncStateless(f),
            };
            (name, f)
        }));
    }
}

/// A set of functions together with their name.
///
/// There should only be a single type that implements `FunctionSet`
/// (namely `StoredFunctionSet`), but this trait is nevertheless
/// useful in order to store `StoredFunctionSet`s of different type
/// within the `Executor`.
#[async_trait]
pub trait FunctionSet {
    async fn exec<'a>(
        &'a self,
        k: &'a str,
        register: &'a Register,
        context: &'a Context<'_>,
    ) -> NaslResult;

    fn contains(&self, k: &str) -> bool;
}

#[async_trait]
impl<State: Sync + Send> FunctionSet for StoredFunctionSet<State> {
    async fn exec<'a>(
        &'a self,
        k: &'a str,
        register: &'a Register,
        context: &'a Context<'_>,
    ) -> NaslResult {
        let f = &self.fns[k];
        match f {
            NaslFunction::AsyncStateful(f) => {
                let state = self.state.read().await;
                f.call_stateful(&state, register, context).await
            }
            NaslFunction::SyncStateful(f) => {
                let state = self.state.read().await;
                f(&state, register, context)
            }
            NaslFunction::AsyncStatefulMut(f) => {
                let mut state = self.state.write().await;
                f.call_stateful(&mut state, register, context).await
            }
            NaslFunction::SyncStatefulMut(f) => {
                let mut state = self.state.write().await;
                f(&mut state, register, context)
            }
            NaslFunction::AsyncStateless(f) => f.call_stateless(register, context).await,
            NaslFunction::SyncStateless(f) => f(register, context),
        }
    }

    fn contains(&self, k: &str) -> bool {
        self.fns.contains_key(k)
    }
}

/// Anything that can be converted into a `StoredFunctionSet`.
pub trait IntoFunctionSet {
    /// The state associated with the function set.
    /// Can be a ZST/marker type for stateless functions.
    type State;
    fn into_function_set(self) -> StoredFunctionSet<Self::State>;
}

#[macro_export]
macro_rules! internal_call_expr {
    ($set_name: ident $(,)?) => {
    };
    ($set_name: ident, ($fn_name: path, $name: literal) $(, $($tt: tt)*)?) => {
        $fn_name(&mut $set_name, $name);
        $(
            $crate::internal_call_expr!($set_name, $($tt)*);
        )?
    };
    ($set_name: ident, $fn_name: path $(, $($tt: tt)*)?) => {
        $fn_name(&mut $set_name, stringify!($fn_name));
        $(
            $crate::internal_call_expr!($set_name, $($tt)*);
        )?
    };
}

/// Convenience macro to define a set of functions.
/// Example:
/// ```rust ignore
/// # use crate::nasl::prelude::*;
/// # use crate::nasl::prelude::*;
/// struct Foo;
///
/// #[nasl_function]
/// fn foo() {
/// }
///
/// #[nasl_function]
/// fn bar() {
/// }
///
/// function_set! {
///    Foo,
///    (
///        foo,
///        bar,
///    )
/// }
/// ```
///
/// This will implement `IntoFunctionSet` for `Foo`, so that it can be
/// used within the executor.
#[macro_export]
macro_rules! function_set {
    ($ty: ty, ($($tt: tt)*)) => {
        impl $crate::nasl::utils::IntoFunctionSet for $ty {
            type State = $ty;

            #[allow(unused_mut)]
            fn into_function_set(self) -> $crate::nasl::utils::StoredFunctionSet<Self::State> {
                let mut set = $crate::nasl::utils::StoredFunctionSet::new(self);
                $crate::internal_call_expr!(set, $($tt)*);
                set
            }
        }
    };
}
