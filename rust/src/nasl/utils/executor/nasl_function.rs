// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{future::Future, pin::Pin};

use crate::nasl::{Context, NaslResult, Register};

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

/// Something that can be called with
/// 1. A state of some type (for example, a list of open SSH connections)
/// 2. A `Register`
/// 3. A `Context`
///
/// This trait exists to make it possible to store async functions inside function sets
/// and is only an internal implementation detail to make the compiler happy.
pub trait StatefulCallable<State> {
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

/// Something that can be called with
/// 1. A mutable reference to a state of some type (for example, a list of open SSH connections)
/// 2. A `Register`
/// 3. A `Context`
///
/// This trait exists to make it possible to store async functions inside function sets
/// and is only an internal implementation detail to make the compiler happy.
pub trait StatefulMutCallable<State> {
    fn call_stateful<'b>(
        &self,
        state: &'b mut State,
        register: &'b Register,
        context: &'b Context,
    ) -> Pin<Box<dyn Future<Output = NaslResult> + Send + 'b>>;
}

impl<F, State> StatefulMutCallable<State> for F
where
    F: for<'a> AsyncTripleArgFn<&'a mut State, &'a Register, &'a Context<'a>, Output = NaslResult>
        + 'static,
{
    fn call_stateful<'b>(
        &self,
        state: &'b mut State,
        register: &'b Register,
        context: &'b Context,
    ) -> Pin<Box<dyn Future<Output = NaslResult> + Send + 'b>> {
        Box::pin((*self)(state, register, context))
    }
}

/// Something that can be called with
/// 1. A `Register`
/// 2. A `Context`
///
/// This trait exists to make it possible to store async functions inside function sets
/// and is only an internal implementation detail to make the compiler happy.
pub trait StatelessCallable {
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

/// Represents one of the six types of NaslFunctions.
/// This type exists in order to make it possible to
/// store a collection of different NASL functions inside
/// a single function set.
pub enum NaslFunction<State> {
    AsyncStateful(Box<dyn StatefulCallable<State> + Send + Sync>),
    SyncStateful(fn(&State, &Register, &Context) -> NaslResult),
    AsyncStatefulMut(Box<dyn StatefulMutCallable<State> + Send + Sync>),
    SyncStatefulMut(fn(&mut State, &Register, &Context) -> NaslResult),
    AsyncStateless(Box<dyn StatelessCallable + Send + Sync>),
    SyncStateless(fn(&Register, &Context) -> NaslResult),
}
