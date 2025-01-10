// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! This module contains tests for the nasl_function proc macro.
//! It would be nicer to have this within the proc_macro crate itself,
//! but testing proc_macros comes with a lot of difficulties and the tests
//! are very easy to do here.

use crate::nasl::{test_prelude::*, utils::Executor};

#[nasl_function]
fn foo1(_context: &Context, x: usize) -> usize {
    x
}

#[nasl_function]
fn foo2(_register: &Register, x: usize) -> usize {
    x
}

#[nasl_function]
fn add_positionals(_x: usize, _y: usize, argv: CheckedPositionals<usize>) -> usize {
    argv.iter().sum()
}

struct Foo;

function_set! {
    Foo,
    (foo1, foo2, add_positionals)
}

/// Tests that the `Context` and `Register` arguments,
/// which may appear before the positional arguments,
/// are not taken into account for determining the index
/// of the positional arguments after them.
#[test]
fn context_and_register_are_ignored_in_positional_index() {
    let mut t = TestBuilder::default().with_executor(Executor::single(Foo));
    t.ok("foo1(5);", 5);
    t.ok("foo2(5);", 5);
}

#[test]
fn variadic_positionals_start_at_correct_index() {
    let mut t = TestBuilder::default().with_executor(Executor::single(Foo));
    t.ok("add_positionals(1, 2, 3, 4);", 7);
}

struct Bar;

impl Bar {
    #[nasl_function]
    fn sync_stateful_ref(&self) -> usize {
        1
    }

    #[nasl_function]
    fn sync_stateful_mut(&mut self) -> usize {
        2
    }

    #[nasl_function]
    async fn async_stateful_ref(&self) -> usize {
        3
    }

    #[nasl_function]
    async fn async_stateful_mut(&mut self) -> usize {
        4
    }
}

#[nasl_function]
async fn sync_stateless() -> usize {
    5
}

#[nasl_function]
async fn async_stateless() -> usize {
    6
}

function_set! {
    Bar,
    (
        (Bar::sync_stateful_ref, "sync_stateful_ref"),
        (Bar::sync_stateful_mut, "sync_stateful_mut"),
        (Bar::async_stateful_ref, "async_stateful_ref"),
        (Bar::async_stateful_mut, "async_stateful_mut"),
        sync_stateless,
        async_stateless,
    )
}

#[test]
fn functions_added_properly() {
    let mut t = TestBuilder::default().with_executor(Executor::single(Bar));
    t.ok("sync_stateful_ref();", 1);
    t.ok("sync_stateful_mut();", 2);
    t.ok("async_stateful_ref();", 3);
    t.ok("async_stateful_mut();", 4);
    t.ok("sync_stateless();", 5);
    t.ok("async_stateless();", 6);
}
