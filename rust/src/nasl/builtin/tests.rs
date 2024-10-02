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

struct Foo;

function_set! {
    Foo,
    sync_stateless,
    (foo1, foo2)
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
