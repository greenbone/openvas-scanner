// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

use nasl_syntax::{Statement, Statement::*, Token};

use crate::{
    error::{FunctionError, InterpretError},
    interpreter::InterpretResult,
    lookup,
    lookup_keys::FC_ANON_ARGS,
    ContextType, Interpreter, NaslValue,
};
use std::collections::HashMap;

/// Is a trait to handle function calls within nasl.
pub(crate) trait CallExtension {
    fn call(&mut self, name: &Token, arguments: &[Statement]) -> InterpretResult;
}

impl<'a, K> CallExtension for Interpreter<'a, K>
where
    K: AsRef<str>,
{
    fn call(&mut self, name: &Token, arguments: &[Statement]) -> InterpretResult {
        let name = &Self::identifier(name)?;
        // get the context
        let mut named = HashMap::new();
        let mut position = vec![];
        // TODO simplify
        for p in arguments {
            match p {
                NamedParameter(token, val) => {
                    let val = self.resolve(val)?;
                    let name = Self::identifier(token)?;
                    named.insert(name, ContextType::Value(val));
                }
                val => {
                    let val = self.resolve(val)?;
                    position.push(val);
                }
            }
        }
        named.insert(
            FC_ANON_ARGS.to_owned(),
            ContextType::Value(NaslValue::Array(position)),
        );
        self.registrat.create_root_child(named);
        let result = match lookup(name) {
            // Built-In Function
            Some(function) => function(self.registrat, self.ctxconfigs)
                .map_err(|x| FunctionError::new(name, x).into()),
            // Check for user defined function
            None => {
                let found = self
                    .registrat
                    .named(name)
                    .ok_or_else(|| InterpretError::not_found(name))?
                    .clone();
                match found {
                    ContextType::Function(params, stmt) => {
                        // prepare default values
                        for p in params {
                            match self.registrat.named(&p) {
                                None => {
                                    // add default NaslValue::Null for each defined params
                                    self.registrat
                                        .add_local(&p, ContextType::Value(NaslValue::Null));
                                }
                                Some(_) => {}
                            }
                        }
                        match self.resolve(&stmt)? {
                            NaslValue::Return(x) => Ok(*x),
                            a => Ok(a),
                        }
                    }
                    ContextType::Value(_) => Err(InterpretError::expected_function()),
                }
            }
        };
        self.registrat.drop_last();
        result
    }
}

#[cfg(test)]
mod tests {
    use nasl_syntax::parse;

    use crate::{context::DefaultContext, context::Register, Interpreter, NaslValue};

    #[test]
    fn default_null_on_user_defined_functions() {
        let code = r###"
        function test(a, b) {
            return a + b;
        }
        test(a: 1, b: 2);
        test(a: 1);
        test();
        "###;
        let mut register = Register::default();
        let binding = DefaultContext::default();
        let context = binding.as_context();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("unexpected parse error")));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
        assert_eq!(parser.next(), Some(Ok(3.into())));
        assert_eq!(parser.next(), Some(Ok(1.into())));
    }
}
