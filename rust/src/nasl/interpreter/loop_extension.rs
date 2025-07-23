// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::nasl::syntax::grammar::{For, ForEach, Repeat, While};

use crate::nasl::prelude::NaslValue;

use super::nasl_value::RuntimeValue;
use super::{Interpreter, Result};

fn value_into_vec(v: NaslValue) -> Vec<NaslValue> {
    match v {
        NaslValue::Array(ret) => ret,
        NaslValue::Dict(ret) => ret.values().cloned().collect(),
        NaslValue::Boolean(_) | NaslValue::Number(_) => vec![v],
        NaslValue::Data(ret) => ret.into_iter().map(|x| NaslValue::Data(vec![x])).collect(),
        NaslValue::String(ret) => ret
            .chars()
            .map(|x| NaslValue::String(x.to_string()))
            .collect(),
        _ => vec![],
    }
}

impl Interpreter<'_> {
    /// Interpreting a NASL for loop. A NASL for loop is built up with the
    /// following:
    ///
    /// for (assignment; condition; update) {body}
    ///
    /// It first resolves the assignment and runs until the condition resolves
    /// into a `FALSE` NaslValue. The update statement is resolved after each
    /// iteration.
    pub async fn resolve_for(
        &mut self,
        For {
            initializer,
            condition,
            increment,
            block,
        }: &For,
    ) -> Result {
        // Resolve assignment
        if let Some(initializer) = initializer {
            self.resolve(initializer).await?;
        }
        loop {
            // Check condition statement
            if !self.resolve_expr(condition).await?.convert_to_boolean() {
                break;
            }

            // Execute loop body
            let ret = self.resolve_block(block).await?;
            // Catch special values
            match ret {
                NaslValue::Break => break,
                NaslValue::Exit(code) => return Ok(NaslValue::Exit(code)),
                NaslValue::Return(val) => return Ok(NaslValue::Return(val)),
                _ => (),
            };

            if let Some(increment) = increment {
                self.resolve(increment).await?;
            }
        }

        Ok(NaslValue::Null)
    }

    /// Interpreting a NASL foreach loop. A NASL foreach loop is built up with
    /// the following:
    ///
    /// foreach variable(iterable) {body}
    ///
    /// The iterable is first transformed into an Array, then we iterate through
    /// it and resolve the body for every value in the array.
    pub async fn resolve_foreach(&mut self, ForEach { var, array, block }: &ForEach) -> Result {
        // Iterate through the iterable Statement
        for val in value_into_vec(self.resolve_expr(array).await?) {
            // Change the value of the iteration variable after each iteration
            self.register
                .add_local(var.to_str(), RuntimeValue::Value(val));

            // Execute loop body
            let ret = self.resolve_block(block).await?;
            // Catch special values
            match ret {
                NaslValue::Break => break,
                NaslValue::Exit(code) => return Ok(NaslValue::Exit(code)),
                NaslValue::Return(val) => return Ok(NaslValue::Return(val)),
                _ => (),
            };
        }

        Ok(NaslValue::Null)
    }

    /// Interpreting a NASL while loop. A NASL while loop is built up with the
    /// following:
    ///
    /// while (condition) {body}
    ///
    /// The condition is first checked, then the body resolved, as long as the
    /// condition resolves into a `TRUE` NaslValue.
    pub async fn resolve_while(&mut self, While { condition, block }: &While) -> Result {
        while self.resolve_expr(condition).await?.convert_to_boolean() {
            // Execute loop body
            let ret = self.resolve_block(block).await?;
            // Catch special values
            match ret {
                NaslValue::Break => break,
                NaslValue::Exit(code) => return Ok(NaslValue::Exit(code)),
                NaslValue::Return(val) => return Ok(NaslValue::Return(val)),
                _ => (),
            };
        }

        Ok(NaslValue::Null)
    }

    /// Interpreting a NASL repeat until loop. A NASL repeat until loop is built
    /// up with the following:
    ///
    /// repeat {body} until (condition);
    ///
    /// It first resolves the body at least once. It keeps resolving the body,
    /// until the condition statement resolves into a `TRUE` NaslValue.
    pub async fn resolve_repeat(&mut self, Repeat { block, condition }: &Repeat) -> Result {
        loop {
            // Execute loop body
            let ret = self.resolve_block(block).await?;
            // Catch special values
            match ret {
                NaslValue::Break => break,
                NaslValue::Exit(code) => return Ok(NaslValue::Exit(code)),
                NaslValue::Return(val) => return Ok(NaslValue::Return(val)),
                _ => (),
            };

            // Check condition statement
            if self.resolve_expr(condition).await?.convert_to_boolean() {
                break;
            }
        }

        Ok(NaslValue::Null)
    }
}

#[cfg(test)]
mod tests {
    use crate::{interpreter_test_ok, nasl::test_prelude::*};

    interpreter_test_ok!(
        for_loop,
        r###"
        a = 0;
        for ( i = 1; i < 5; i++) {
            a += i;
        }
        a;
        "###,
        0,
        NaslValue::Null,
        10
    );

    interpreter_test_ok!(
        for_loop_without_update,
        r###"
        a = 0;
        for (; a < 5; ) {
            a += 1;
        }
        a;
        "###,
        0,
        NaslValue::Null,
        5
    );

    interpreter_test_ok!(
        for_each_loop,
        r###"
        arr[0] = 3;
        arr[1] = 5;
        a = 0;
        foreach i (arr) {
            a += i;
        }
        a;
        "###,
        3,
        5,
        0,
        NaslValue::Null,
        8
    );

    interpreter_test_ok!(
        while_loop,
        r###"
        i = 4;
        a = 0;
        i > 0;
        while(i > 0) {
            a += i;
            i--;
        }
        a;
        i;
        "###,
        4,
        0,
        NaslValue::Boolean(true),
        NaslValue::Null,
        10,
        0,
    );

    interpreter_test_ok!(
        repeat_loop,
        r###"
        i = 10;
        a = 0;
        repeat {
            a += i;
            i--;
        } until (i > 0);
        a;
        i;
        "###,
        10,
        0,
        NaslValue::Null,
        10,
        9
    );

    interpreter_test_ok!(
        control_flow,
        r###"
        a = 0;
        i = 5;
        while(i > 0) {
            if(i == 4) {
                i--;
                continue;
            }
            if (i == 1) {
                break;
            }
            a += i;
            i--;
        }
        a;
        i;
        "###,
        0,
        5,
        NaslValue::Null,
        10,
        1
    );
}
