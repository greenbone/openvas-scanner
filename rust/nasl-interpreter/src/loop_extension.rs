// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use nasl_syntax::{IdentifierType, Statement, Token, TokenCategory};

use crate::{interpreter::InterpretResult, InterpretError, Interpreter};
use nasl_builtin_utils::ContextType;
use nasl_syntax::NaslValue;

/// Extension to handle the interpretation of NASL loops
pub(crate) trait LoopExtension {
    /// Interpreting a NASL for loop. A NASL for loop is built up with the
    /// following:
    ///
    /// for (assignment; condition; update) {body}
    ///
    /// It first resolves the assignment and runs until the condition resolves
    /// into a `FALSE` NaslValue. The update statement is resolved after each
    /// iteration.
    fn for_loop(
        &mut self,
        assignment: &Statement,
        condition: &Statement,
        update: &Statement,
        body: &Statement,
    ) -> InterpretResult;

    /// Interpreting a NASL foreach loop. A NASL foreach loop is built up with
    /// the following:
    ///
    /// foreach variable(iterable) {body}
    ///
    /// The iterable is first transformed into an Array, then we iterate through
    /// it and resolve the body for every value in the array.
    fn while_loop(&mut self, condition: &Statement, body: &Statement) -> InterpretResult;

    /// Interpreting a NASL while loop. A NASL while loop is built up with the
    /// following:
    ///
    /// while (condition) {body}
    ///
    /// The condition is first checked, then the body resolved, as long as the
    /// condition resolves into a `TRUE` NaslValue.
    fn repeat_loop(&mut self, body: &Statement, condition: &Statement) -> InterpretResult;

    /// Interpreting a NASL repeat until loop. A NASL repeat until loop is built
    /// up with the following:
    ///
    /// repeat {body} until (condition);
    ///
    /// It first resolves the body at least once. It keeps resolving the body,
    /// until the condition statement resolves into a `TRUE` NaslValue.
    fn for_each_loop(
        &mut self,
        variable: &Token,
        iterable: &Statement,
        body: &Statement,
    ) -> InterpretResult;
}

/// Implementation for the Loop extension. Note that for all loops, we do not
/// change the context, as the current NASL also does not change it too.
impl<'a, K> LoopExtension for Interpreter<'a, K>
where
    K: AsRef<str>,
{
    fn for_loop(
        &mut self,
        assignment: &Statement,
        condition: &Statement,
        update: &Statement,
        body: &Statement,
    ) -> InterpretResult {
        // Resolve assignment
        self.resolve(assignment)?;

        loop {
            // Check condition statement
            if !bool::from(self.resolve(condition)?) {
                break;
            }

            // Execute loop body
            let ret = self.resolve(body)?;
            // Catch special values
            match ret {
                NaslValue::Break => break,
                NaslValue::Exit(code) => return Ok(NaslValue::Exit(code)),
                NaslValue::Return(val) => return Ok(NaslValue::Return(val)),
                _ => (),
            };

            // Execute update Statement
            self.resolve(update)?;
        }

        Ok(NaslValue::Null)
    }

    fn for_each_loop(
        &mut self,
        variable: &Token,
        iterable: &Statement,
        body: &Statement,
    ) -> InterpretResult {
        // Get name of the iteration variable
        let iter_name = match variable.category() {
            TokenCategory::Identifier(IdentifierType::Undefined(name)) => name,
            o => return Err(InterpretError::wrong_category(o)),
        };
        // Iterate through the iterable Statement
        for val in Vec::<NaslValue>::from(self.resolve(iterable)?) {
            // Change the value of the iteration variable after each iteration
            self.register_mut()
                .add_local(iter_name, ContextType::Value(val));

            // Execute loop body
            let ret = self.resolve(body)?;
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

    fn while_loop(&mut self, condition: &Statement, body: &Statement) -> InterpretResult {
        while bool::from(self.resolve(condition)?) {
            // Execute loop body
            let ret = self.resolve(body)?;
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

    fn repeat_loop(&mut self, body: &Statement, condition: &Statement) -> InterpretResult {
        loop {
            // Execute loop body
            let ret = self.resolve(body)?;
            // Catch special values
            match ret {
                NaslValue::Break => break,
                NaslValue::Exit(code) => return Ok(NaslValue::Exit(code)),
                NaslValue::Return(val) => return Ok(NaslValue::Return(val)),
                _ => (),
            };

            // Check condition statement
            if bool::from(self.resolve(condition)?) {
                break;
            }
        }

        Ok(NaslValue::Null)
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn for_loop_test() {
        let code = r###"
        a = 0;
        for ( i = 1; i < 5; i++) {
            a += i;
        }
        a;
        "###;
        let binding = ContextBuilder::default();
        let context = binding.build();
        let register = Register::default();
        let mut interpreter = Interpreter::new(register, &context);
        let mut interpreter =
            parse(code).map(|x| interpreter.resolve(&x.expect("unexpected parse error")));
        assert_eq!(interpreter.next(), Some(Ok(0.into())));
        assert_eq!(interpreter.next(), Some(Ok(NaslValue::Null)));
        assert_eq!(interpreter.next(), Some(Ok(10.into())));
    }

    #[test]
    fn for_loop_without_update() {
        let code = r###"
        a = 0;
        for (; a < 5; ) {
            a += 1;
        }
        a;
        "###;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut interpreter = Interpreter::new(register, &context);
        let mut interpreter =
            parse(code).map(|x| interpreter.resolve(&x.expect("unexpected parse error")));
        assert_eq!(interpreter.next(), Some(Ok(0.into())));
        assert_eq!(interpreter.next(), Some(Ok(NaslValue::Null)));
        assert_eq!(interpreter.next(), Some(Ok(5.into())));
    }

    #[test]
    fn for_each_loop_test() {
        let code = r###"
        arr[0] = 3;
        arr[1] = 5;
        a = 0;
        foreach i (arr) {
            a += i;
        }
        a;
        "###;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut interpreter = Interpreter::new(register, &context);
        let mut interpreter =
            parse(code).map(|x| interpreter.resolve(&x.expect("unexpected parse error")));
        assert_eq!(interpreter.next(), Some(Ok(3.into())));
        assert_eq!(interpreter.next(), Some(Ok(5.into())));
        assert_eq!(interpreter.next(), Some(Ok(0.into())));
        assert_eq!(interpreter.next(), Some(Ok(NaslValue::Null)));
        assert_eq!(interpreter.next(), Some(Ok(8.into())));
    }

    #[test]
    fn while_loop_test() {
        let code = r###"
        i = 4;
        a = 0;
        i > 0;
        while(i > 0) {
            a += i;
            i--;
        }
        a;
        i;
        "###;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut interpreter = Interpreter::new(register, &context);
        let mut interpreter =
            parse(code).map(|x| interpreter.resolve(&x.expect("unexpected parse error")));
        assert_eq!(interpreter.next(), Some(Ok(4.into())));
        assert_eq!(interpreter.next(), Some(Ok(0.into())));
        assert_eq!(interpreter.next(), Some(Ok(NaslValue::Boolean(true))));

        assert_eq!(interpreter.next(), Some(Ok(NaslValue::Null)));
        assert_eq!(interpreter.next(), Some(Ok(10.into())));
        assert_eq!(interpreter.next(), Some(Ok(0.into())));
    }

    #[test]
    fn repeat_loop_test() {
        let code = r###"
        i = 10;
        a = 0;
        repeat {
            a += i;
            i--;
        } until (i > 0);
        a;
        i;
        "###;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut interpreter = Interpreter::new(register, &context);
        let mut interpreter =
            parse(code).map(|x| interpreter.resolve(&x.expect("unexpected parse error")));
        assert_eq!(interpreter.next(), Some(Ok(10.into())));
        assert_eq!(interpreter.next(), Some(Ok(0.into())));
        assert_eq!(interpreter.next(), Some(Ok(NaslValue::Null)));
        assert_eq!(interpreter.next(), Some(Ok(10.into())));
        assert_eq!(interpreter.next(), Some(Ok(9.into())));
    }

    #[test]
    fn control_flow() {
        let code = r###"
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
        "###;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut interpreter = Interpreter::new(register, &context);
        let mut interpreter =
            parse(code).map(|x| interpreter.resolve(&x.expect("unexpected parse error")));
        assert_eq!(interpreter.next(), Some(Ok(0.into())));
        assert_eq!(interpreter.next(), Some(Ok(5.into())));
        assert_eq!(interpreter.next(), Some(Ok(NaslValue::Null)));
        assert_eq!(interpreter.next(), Some(Ok(10.into())));
        assert_eq!(interpreter.next(), Some(Ok(1.into())));
    }
}
