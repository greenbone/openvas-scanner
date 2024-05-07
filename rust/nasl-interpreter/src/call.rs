// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use nasl_builtin_utils::lookup_keys::FC_ANON_ARGS;
use nasl_syntax::{Statement, StatementKind::*, Token};

use crate::{
    error::{FunctionError, InterpretError},
    interpreter::InterpretResult,
    Interpreter,
};

use nasl_builtin_utils::ContextType;
use nasl_syntax::NaslValue;
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
            match p.kind() {
                NamedParameter(val) => {
                    let val = self.resolve(val)?;
                    let name = Self::identifier(p.as_token())?;
                    named.insert(name, ContextType::Value(val));
                }
                _ => {
                    let val = self.resolve(p)?;
                    position.push(val);
                }
            }
        }
        named.insert(
            FC_ANON_ARGS.to_owned(),
            ContextType::Value(NaslValue::Array(position)),
        );
        self.registrat.create_root_child(named);
        let result = match self.ctxconfigs.nasl_fn_execute(name, &self.registrat) {
            Some(r) => {
                if let Ok(NaslValue::Fork(mut x)) = r {
                    Ok(if let Some(r) = x.pop() {
                        // this is a proposal for the case that the caller is immediately executing
                        // if not the position needs to be reset
                        let position = self.position.current_init_statement();
                        for i in x {
                            tracing::trace!(return_value=?i, return_position=?self.position, interpreter_position=?position, "creating interpreter instance" );
                            self.forked_interpreter.push(Self {
                                registrat: self.registrat.clone(),
                                ctxconfigs: self.ctxconfigs,
                                position: position.clone(),
                                skip_until_return: Some((self.position.clone(), i)),
                                forked_interpreter: vec![],
                                forked_interpreter_index: 0,
                            });
                        }
                        tracing::trace!(return_value=?r, "returning interpreter instance" );
                        r
                    } else {
                        NaslValue::Null
                    })
                } else {
                    r.map_err(|x| FunctionError::new(name, x).into())
                }
            }
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
    use crate::*;

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
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
        assert_eq!(parser.next(), Some(Ok(3.into())));
        assert_eq!(parser.next(), Some(Ok(1.into())));
    }
}
