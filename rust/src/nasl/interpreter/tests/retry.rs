// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Checks that errors that specify that they are solvable by
//! retrying are actually retried within the interpreter.

use crate::nasl::{test_prelude::*, utils::Executor};

struct Counter {
    count: usize,
}

impl Counter {
    fn check_and_increment(&mut self) -> Result<usize, FnError> {
        self.count += 1;
        if self.count < 5 {
            // Return a dummy error, it doesnt matter what it is.
            Err(FnError::from(ArgumentError::WrongArgument("test".into())))
        } else {
            Ok(self.count)
        }
    }

    #[nasl_function]
    fn check_counter_retry(&mut self) -> Result<usize, FnError> {
        self.check_and_increment().map_err(|e| e.with(Retryable))
    }

    #[nasl_function]
    fn check_counter(&mut self) -> Result<usize, FnError> {
        self.check_and_increment()
    }
}

function_set! {
    Counter,
    (
        (Counter::check_counter_retry, "check_counter_retry"),
        (Counter::check_counter, "check_counter"),
    )
}

#[test]
fn retryable_error() {
    let mut t = TestBuilder::default().with_executor(Executor::single(Counter { count: 0 }));
    check_err_matches!(t, "check_counter();", ArgumentError::WrongArgument(_));
    t.ok("check_counter_retry();", 5);
}
