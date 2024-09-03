use std::{collections::HashMap, future::Future, pin::Pin};

use crate::{Context, NaslResult, Register};

/// A wrapper trait to represent a function taking two arguments.
/// This trait exists to allow attaching the lifetime of the HRTB
/// lifetime to something. For more info, see
/// https://users.rust-lang.org/t/lifetimes-with-async-function-parameters/51338
/// Unfortunately, this trait needs to be public, but it should
/// not be implemented on any struct other than two-argument functions.
pub trait AsyncDoubleArgFn<Arg1, Arg2>:
    Fn(Arg1, Arg2) -> <Self as AsyncDoubleArgFn<Arg1, Arg2>>::Fut
{
    type Fut: Future<Output = <Self as AsyncDoubleArgFn<Arg1, Arg2>>::Output> + Send;
    type Output;
}

impl<Arg1, Arg2, F, Fut> AsyncDoubleArgFn<Arg1, Arg2> for F
where
    F: Fn(Arg1, Arg2) -> Fut,
    Fut: Future + Send,
{
    type Fut = Fut;
    type Output = Fut::Output;
}

/// A wrapper trait to represent a function taking three arguments.
/// This trait exists to allow attaching the lifetime of the HRTB
/// lifetime to something. For more info, see
/// https://users.rust-lang.org/t/lifetimes-with-async-function-parameters/51338
/// Unfortunately, this trait needs to be public, but it should
/// not be implemented on any struct other than three-argument functions.
pub trait AsyncTripleArgFn<Arg1, Arg2, Arg3>:
    Fn(Arg1, Arg2, Arg3) -> <Self as AsyncTripleArgFn<Arg1, Arg2, Arg3>>::Fut + Send
{
    type Fut: Future<Output = <Self as AsyncTripleArgFn<Arg1, Arg2, Arg3>>::Output> + Send;
    type Output;
}

impl<Arg1, Arg2, Arg3, F, Fut> AsyncTripleArgFn<Arg1, Arg2, Arg3> for F
where
    F: Fn(Arg1, Arg2, Arg3) -> Fut + Send,
    Fut: Future + Send,
{
    type Fut = Fut;
    type Output = Fut::Output;
}

enum NaslFunction<State> {
    Async(Box<dyn StatefulCallable<State> + Send + Sync>),
    Sync(fn(&State, &Register, &Context) -> NaslResult),
    AsyncStateless(Box<dyn StatelessCallable + Send + Sync>),
    SyncStateless(fn(&Register, &Context) -> NaslResult),
}

trait StatefulCallable<State> {
    fn call_stateful<'b>(
        &self,
        state: &'b State,
        register: &'b Register,
        context: &'b Context,
    ) -> Pin<Box<dyn Future<Output = NaslResult> + Send + 'b>>;
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
    ) -> Pin<Box<dyn Future<Output = NaslResult> + Send + 'b>> {
        Box::pin((*self)(state, register, context))
    }
}

trait StatelessCallable {
    fn call_stateless<'b>(
        &self,
        register: &'b Register,
        context: &'b Context,
    ) -> Pin<Box<dyn Future<Output = NaslResult> + Send + 'b>>;
}

impl<F> StatelessCallable for F
where
    F: for<'a> AsyncDoubleArgFn<&'a Register, &'a Context<'a>, Output = NaslResult> + 'static,
{
    fn call_stateless<'b>(
        &self,
        register: &'b Register,
        context: &'b Context,
    ) -> Pin<Box<dyn Future<Output = NaslResult> + Send + 'b>> {
        Box::pin((*self)(register, context))
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
            .insert(k.to_string(), NaslFunction::Async(Box::new(v)));
    }

    pub fn sync_stateful(&mut self, k: &str, v: fn(&State, &Register, &Context) -> NaslResult) {
        self.fns.insert(k.to_string(), NaslFunction::Sync(v));
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

    pub fn add_set<State2>(
        &mut self,
        other: impl IntoFunctionSet<Set = StoredFunctionSet<State2>>,
    ) {
        let set = other.into_function_set();
        self.fns.extend(set.fns.into_iter().map(|(name, f)| {
            let f: NaslFunction<State> = match f {
                NaslFunction::Async(_) => unimplemented!(),
                NaslFunction::Sync(_) => unimplemented!(),
                NaslFunction::AsyncStateless(f) => NaslFunction::AsyncStateless(f),
                NaslFunction::SyncStateless(f) => NaslFunction::SyncStateless(f),
            };
            (name, f)
        }));
    }
}

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
            NaslFunction::Async(f) => Box::new(f.call_stateful(&self.state, register, context)),
            NaslFunction::Sync(f) => {
                Box::new(Box::pin(async { f(&self.state, register, context) }))
            }
            NaslFunction::AsyncStateless(f) => Box::new(f.call_stateless(register, context)),
            NaslFunction::SyncStateless(f) => Box::new(Box::pin(async { f(register, context) })),
        })
    }

    fn contains(&self, k: &str) -> bool {
        self.fns.get(k).is_some()
    }
}

pub trait IntoFunctionSet {
    type Set: FunctionSet + Send + Sync;
    fn into_function_set(self) -> Self::Set;
}

#[derive(Default)]
pub struct Executor {
    sets: Vec<Box<dyn FunctionSet + Send + Sync>>,
}

impl Executor {
    pub fn single<S: IntoFunctionSet + 'static>(s: S) -> Self {
        let mut exec = Self::default();
        exec.add_set(s);
        exec
    }

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

#[macro_export]
macro_rules! function_set {
    ($ty: ty, $method_name: ident, ($($tt: tt)*)) => {
        impl $crate::IntoFunctionSet for $ty {
            type Set = $crate::StoredFunctionSet<$ty>;

            fn into_function_set(self) -> Self::Set {
                let mut set = $crate::StoredFunctionSet::new(self);
                $crate::internal_call_expr!($method_name, set, $($tt)*);
                set
            }
        }
    };
}
