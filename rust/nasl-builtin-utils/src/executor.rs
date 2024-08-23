use std::{collections::HashMap, future::Future, pin::Pin};

use crate::{Context, NaslResult, Register};

/// A wrapper trait to represent a function taking two arguments.
/// This trait exists to allow attaching the lifetime of the HRTB
/// lifetime to something. For more info, see
/// https://users.rust-lang.org/t/lifetimes-with-async-function-parameters/51338
pub trait AsyncDoubleArgFn<Arg1, Arg2>:
    Fn(Arg1, Arg2) -> <Self as AsyncDoubleArgFn<Arg1, Arg2>>::Fut
{
    type Fut: Future<Output = <Self as AsyncDoubleArgFn<Arg1, Arg2>>::Output>;
    type Output;
}

impl<Arg1, Arg2, F, Fut> AsyncDoubleArgFn<Arg1, Arg2> for F
where
    F: Fn(Arg1, Arg2) -> Fut,
    Fut: Future,
{
    type Fut = Fut;
    type Output = Fut::Output;
}

/// A wrapper trait to represent a function taking three arguments.
/// This trait exists to allow attaching the lifetime of the HRTB
/// lifetime to something. For more info, see
/// https://users.rust-lang.org/t/lifetimes-with-async-function-parameters/51338
pub trait AsyncTripleArgFn<Arg1, Arg2, Arg3>:
    Fn(Arg1, Arg2, Arg3) -> <Self as AsyncTripleArgFn<Arg1, Arg2, Arg3>>::Fut
{
    type Fut: Future<Output = <Self as AsyncTripleArgFn<Arg1, Arg2, Arg3>>::Output>;
    type Output;
}

impl<Arg1, Arg2, Arg3, F, Fut> AsyncTripleArgFn<Arg1, Arg2, Arg3> for F
where
    F: Fn(Arg1, Arg2, Arg3) -> Fut,
    Fut: Future,
{
    type Fut = Fut;
    type Output = Fut::Output;
}

enum StatefulNaslFunction<State> {
    Async(Box<dyn StatefulCallable<State>>),
    Sync(fn(&State, &Register, &Context) -> NaslResult),
}

enum StatelessNaslFunction {
    Async(Box<dyn StatelessCallable>),
    Sync(fn(&Register, &Context) -> NaslResult),
}

trait StatefulCallable<State> {
    fn call_stateful<'b>(
        &self,
        state: &'b State,
        register: &'b Register,
        context: &'b Context,
    ) -> Pin<Box<dyn Future<Output = NaslResult> + 'b>>;
}

impl<F, State> StatefulCallable<State> for F
where
    F: for<'a> AsyncTripleArgFn<&'a State, &'a Register, &'a Context<'a>, Output = NaslResult>
        + 'static,
{
    fn call_stateful<'b>(
        &self,
        state: &'b State,
        register: &'b Register,
        context: &'b Context,
    ) -> Pin<Box<dyn Future<Output = NaslResult> + 'b>> {
        Box::pin((*self)(state, register, context))
    }
}

trait StatelessCallable {
    fn call_stateless<'b>(
        &self,
        register: &'b Register,
        context: &'b Context,
    ) -> Pin<Box<dyn Future<Output = NaslResult> + 'b>>;
}

impl<F> StatelessCallable for F
where
    F: for<'a> AsyncDoubleArgFn<&'a Register, &'a Context<'a>, Output = NaslResult> + 'static,
{
    fn call_stateless<'b>(
        &self,
        register: &'b Register,
        context: &'b Context,
    ) -> Pin<Box<dyn Future<Output = NaslResult> + 'b>> {
        Box::pin((*self)(register, context))
    }
}

/// Todo doc
pub struct StatefulFunctionSet<State> {
    state: State,
    fns: HashMap<String, StatefulNaslFunction<State>>,
}

impl<State> StatefulFunctionSet<State> {
    /// TODO doc
    pub fn new(state: State) -> Self {
        Self {
            state,
            fns: HashMap::new(),
        }
    }

    /// TODO doc
    pub fn add_async<F>(&mut self, k: &str, v: F)
    where
        F: for<'a> AsyncTripleArgFn<&'a State, &'a Register, &'a Context<'a>, Output = NaslResult>
            + 'static,
    {
        self.fns
            .insert(k.to_string(), StatefulNaslFunction::Async(Box::new(v)));
    }

    /// TODO doc
    pub fn add_sync(&mut self, k: &str, v: fn(&State, &Register, &Context) -> NaslResult) {
        self.fns
            .insert(k.to_string(), StatefulNaslFunction::Sync(v));
    }
}

/// Todo doc
pub struct StatelessFunctionSet {
    fns: HashMap<String, StatelessNaslFunction>,
}

impl StatelessFunctionSet {
    /// TODO doc
    pub fn new() -> Self {
        Self {
            fns: HashMap::new(),
        }
    }

    /// TODO doc
    pub fn add_async<F>(&mut self, k: &str, v: F)
    where
        F: for<'a> AsyncDoubleArgFn<&'a Register, &'a Context<'a>, Output = NaslResult> + 'static,
    {
        self.fns
            .insert(k.to_string(), StatelessNaslFunction::Async(Box::new(v)));
    }

    /// TODO doc
    pub fn add_sync(&mut self, k: &str, v: fn(&Register, &Context) -> NaslResult) {
        self.fns
            .insert(k.to_string(), StatelessNaslFunction::Sync(v));
    }

    /// TODO doc
    pub fn set<F: IntoFunctionSet<Set = Self>>(&mut self, f: F) {
        let set = F::into_function_set(f);
        self.fns.extend(set.fns.into_iter())
    }
}

trait FunctionSet {
    fn exec<'a>(
        &'a self,
        k: &'a str,
        register: &'a Register,
        context: &'a Context<'_>,
    ) -> Option<Box<dyn Future<Output = NaslResult> + Unpin + 'a>>;

    fn contains(&self, k: &str) -> bool;
}

impl<State> FunctionSet for StatefulFunctionSet<State> {
    fn exec<'a>(
        &'a self,
        k: &'a str,
        register: &'a Register,
        context: &'a Context<'_>,
    ) -> Option<Box<dyn Future<Output = NaslResult> + Unpin + 'a>> {
        let f = self.fns.get(k)?;
        Some(match f {
            StatefulNaslFunction::Async(f) => {
                Box::new(f.call_stateful(&self.state, register, context))
            }
            StatefulNaslFunction::Sync(f) => {
                Box::new(Box::pin(async { f(&self.state, register, context) }))
            }
        })
    }

    fn contains(&self, k: &str) -> bool {
        self.fns.get(k).is_some()
    }
}

impl FunctionSet for StatelessFunctionSet {
    fn exec<'a>(
        &'a self,
        k: &'a str,
        register: &'a Register,
        context: &'a Context<'_>,
    ) -> Option<Box<dyn Future<Output = NaslResult> + Unpin + 'a>> {
        let f = self.fns.get(k)?;
        Some(match f {
            StatelessNaslFunction::Async(f) => Box::new(f.call_stateless(register, context)),
            StatelessNaslFunction::Sync(f) => Box::new(Box::pin(async { f(register, context) })),
        })
    }

    fn contains(&self, k: &str) -> bool {
        self.fns.get(k).is_some()
    }
}

/// Todo doc
pub trait IntoFunctionSet {
    /// TODO doc
    type Set: FunctionSet;
    /// TODO doc
    fn into_function_set(self) -> Self::Set;
}

#[derive(Default)]
/// TODO doc
pub struct Executor {
    sets: Vec<Box<dyn FunctionSet>>,
}

impl Executor {
    /// Todo doc
    pub fn add_set<S: IntoFunctionSet + 'static>(&mut self, s: S) -> &mut Self {
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

#[macro_export]
/// TODO: doc
macro_rules! stateful_function_set {
    ($ty: ty, $method_name: ident, ($($fn_name: path),*$(,)?)) => {
        impl $crate::IntoFunctionSet for $ty {
            type Set = $crate::StatefulFunctionSet<$ty>;

            fn into_function_set(self) -> Self::Set {
                let mut set = $crate::StatefulFunctionSet::new(self);
                $(
                    set.$method_name(stringify!($fn_name), $fn_name);
                )*
                set
            }
        }
    };
}

#[macro_export]
/// TODO: doc
macro_rules! stateless_function_set {
    ($ty: ty, $method_name: ident, ($($fn_name: path),*$(,)?)) => {
        impl $crate::IntoFunctionSet for $ty {
            type Set = $crate::StatelessFunctionSet;

            fn into_function_set(self) -> Self::Set {
                let mut set = $crate::StatelessFunctionSet::new();
                $(
                    set.$method_name(stringify!($fn_name), $fn_name);
                )*
                set
            }
        }
    };
}

#[macro_export]
/// TODO: doc
macro_rules! combine_function_sets {
    ($ty: ty, ($($set_name: path),*$(,)?)) => {
        impl $crate::IntoFunctionSet for $ty {
            type Set = $crate::StatelessFunctionSet;

            fn into_function_set(self) -> Self::Set {
                let mut set = $crate::StatelessFunctionSet::new();
                $(
                    set.set($set_name);
                )*
                set
            }
        }
    }
}
