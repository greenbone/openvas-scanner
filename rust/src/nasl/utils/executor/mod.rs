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
//!
//! In order to create new sets of NASL functions, the `function_set!` macro is provided.
mod nasl_function;

use std::{collections::HashMap, future::Future};

use nasl_function::{AsyncDoubleArgFn, AsyncTripleArgFn, NaslFunction};

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
        let entry = self
            .sets
            .iter()
            .filter_map(|set| set.exec(k, register, context))
            .next()?;

        Some(entry.await)
    }

    pub fn contains(&self, k: &str) -> bool {
        self.sets.iter().any(|set| set.contains(k))
    }
}

pub struct StoredFunctionSet<State> {
    state: State,
    fns: HashMap<String, NaslFunction<State>>,
}

impl<State> StoredFunctionSet<State> {
    pub fn new(state: State) -> Self {
        Self {
            state,
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
pub trait FunctionSet {
    fn exec<'a>(
        &'a self,
        k: &'a str,
        register: &'a Register,
        context: &'a Context<'_>,
    ) -> Option<Box<dyn Future<Output = NaslResult> + Send + Unpin + 'a>>;

    fn contains(&self, k: &str) -> bool;
}

impl<State: Sync> FunctionSet for StoredFunctionSet<State> {
    fn exec<'a>(
        &'a self,
        k: &'a str,
        register: &'a Register,
        context: &'a Context<'_>,
    ) -> Option<Box<dyn Future<Output = NaslResult> + Send + Unpin + 'a>> {
        let f = self.fns.get(k)?;
        Some(match f {
            NaslFunction::AsyncStateful(f) => {
                Box::new(f.call_stateful(&self.state, register, context))
            }
            NaslFunction::SyncStateful(f) => {
                Box::new(Box::pin(async { f(&self.state, register, context) }))
            }
            NaslFunction::AsyncStateless(f) => Box::new(f.call_stateless(register, context)),
            NaslFunction::SyncStateless(f) => Box::new(Box::pin(async { f(register, context) })),
        })
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
    ($method_name: ident, $set_name: ident $(,)?) => {
    };
    ($method_name: ident, $set_name: ident, ($fn_name: path, $name: literal) $(, $($tt: tt)*)?) => {
        $set_name.$method_name($name, $fn_name);
        $(
            $crate::internal_call_expr!($method_name, $set_name, $($tt)*);
        )?
    };
    ($method_name: ident, $set_name: ident, $fn_name: path $(, $($tt: tt)*)?) => {
        $set_name.$method_name(stringify!($fn_name), $fn_name);
        $(
            $crate::internal_call_expr!($method_name, $set_name, $($tt)*);
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
///    sync_stateless,
///    (
///        foo,
///        bar,
///    )
/// }
/// ```
///
/// This will implement `IntoFunctionSet` for `Foo`, so that it can be
/// used within the executor.
///
/// Depending on the asyncness and statefulness of the NASL functions
/// that one wants to add, the second argument should be one of the following
/// four:
///
/// 1. `async_stateful` (for `async fn(&S, &Register, &Context)`)
/// 2. `sync_stateful` (for `fn(&S, &Register, &Context)`)
/// 3. `async_stateless` (for `async fn(&Register, &Context)`)
/// 4. `sync_stateless` (for `fn(&Register, &Context)`)
#[macro_export]
macro_rules! function_set {
    ($ty: ty, $method_name: ident, ($($tt: tt)*)) => {
        impl $crate::nasl::utils::IntoFunctionSet for $ty {
            type State = $ty;

            #[allow(unused_mut)]
            fn into_function_set(self) -> $crate::nasl::utils::StoredFunctionSet<Self::State> {
                let mut set = $crate::nasl::utils::StoredFunctionSet::new(self);
                $crate::internal_call_expr!($method_name, set, $($tt)*);
                set
            }
        }
    };
}
