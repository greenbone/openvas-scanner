use std::{collections::HashMap, future::Future, pin::Pin};

use crate::{Context, NaslResult, Register};

/// A wrapper trait to represent a function taking two arguments.
/// This trait exists to allow attaching the lifetime of the HRTB
/// lifetime to something. For more info, see
/// https://users.rust-lang.org/t/lifetimes-with-async-function-parameters/51338
trait AsyncDoubleArgFn<Arg1, Arg2>:
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
trait AsyncTripleArgFn<Arg1, Arg2, Arg3>:
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

enum NaslFunction<State> {
    Stateful(Box<dyn StatefulNaslFunction<State>>),
    Stateless(Box<dyn StatelessNaslFunction>),
}

trait StatefulNaslFunction<State> {
    fn call_stateful<'b>(
        &self,
        state: &'b State,
        context: &'b Context,
        register: &'b Register,
    ) -> Pin<Box<dyn Future<Output = NaslResult> + 'b>>;
}

impl<F, State> StatefulNaslFunction<State> for F
where
    F: for<'a> AsyncTripleArgFn<&'a State, &'a Context<'a>, &'a Register, Output = NaslResult>
        + 'static,
{
    fn call_stateful<'b>(
        &self,
        state: &'b State,
        context: &'b Context,
        register: &'b Register,
    ) -> Pin<Box<dyn Future<Output = NaslResult> + 'b>> {
        Box::pin((*self)(state, context, register))
    }
}

trait StatelessNaslFunction {
    fn call_stateless<'b>(
        &self,
        context: &'b Context,
        register: &'b Register,
    ) -> Pin<Box<dyn Future<Output = NaslResult> + 'b>>;
}

impl<F> StatelessNaslFunction for F
where
    F: for<'a> AsyncDoubleArgFn<&'a Context<'a>, &'a Register, Output = NaslResult> + 'static,
{
    fn call_stateless<'b>(
        &self,
        context: &'b Context,
        register: &'b Register,
    ) -> Pin<Box<dyn Future<Output = NaslResult> + 'b>> {
        Box::pin((*self)(context, register))
    }
}

struct StoredFunctionSet<State> {
    state: State,
    fns: HashMap<String, NaslFunction<State>>,
}

impl<State> StoredFunctionSet<State> {
    fn new(state: State) -> Self {
        Self {
            state,
            fns: HashMap::new(),
        }
    }

    fn add_async_stateful<F>(&mut self, k: &str, v: F)
    where
        F: for<'a> AsyncTripleArgFn<&'a State, &'a Context<'a>, &'a Register, Output = NaslResult>
            + 'static,
    {
        self.fns
            .insert(k.to_string(), NaslFunction::Stateful(Box::new(v)));
    }

    fn add_async_stateless<F>(&mut self, k: &str, v: F)
    where
        F: for<'a> AsyncDoubleArgFn<&'a Context<'a>, &'a Register, Output = NaslResult> + 'static,
    {
        self.fns
            .insert(k.to_string(), NaslFunction::Stateless(Box::new(v)));
    }
}

trait FunctionSet {
    fn exec<'a>(
        &'a self,
        k: &'a str,
        context: &'a Context<'_>,
        register: &'a Register,
    ) -> Option<Box<dyn Future<Output = NaslResult> + Unpin + 'a>>;
}

impl<State> FunctionSet for StoredFunctionSet<State> {
    fn exec<'a>(
        &'a self,
        k: &'a str,
        context: &'a Context<'_>,
        register: &'a Register,
    ) -> Option<Box<dyn Future<Output = NaslResult> + Unpin + 'a>> {
        let f = self.fns.get(k)?;
        Some(match f {
            NaslFunction::Stateful(f) => Box::new(f.call_stateful(&self.state, context, register)),
            NaslFunction::Stateless(f) => Box::new(f.call_stateless(context, register)),
        })
    }
}

#[derive(Default)]
struct Executor {
    sets: Vec<Box<dyn FunctionSet>>,
    keys: Vec<String>,
}

impl Executor {
    fn add_set(&mut self, set: impl FunctionSet + 'static) {
        self.sets.push(Box::new(set));
    }

    async fn exec(
        &self,
        k: &str,
        context: &Context<'_>,
        register: &Register,
    ) -> Option<NaslResult> {
        let entry = self
            .sets
            .iter()
            .filter_map(|set| set.exec(k, context, register))
            .next()?;

        Some(entry.await)
    }
}
