// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::nasl::syntax::{Statement, StatementKind::*, Token};
use crate::nasl::utils::lookup_keys::FC_ANON_ARGS;

use crate::nasl::interpreter::{
    error::{FunctionError, InterpretError},
    interpreter::{InterpretResult, RunSpecific},
    Interpreter,
};

use crate::nasl::syntax::NaslValue;
use crate::nasl::utils::ContextType;
use std::collections::HashMap;

impl<'a> Interpreter<'a> {
    pub async fn call(&mut self, name: &Token, arguments: &[Statement]) -> InterpretResult {
        let name = &Self::identifier(name)?;
        // get the context
        let mut named = HashMap::new();
        let mut position = vec![];
        // TODO simplify
        for p in arguments {
            match p.kind() {
                NamedParameter(val) => {
                    let val = self.resolve(val).await?;
                    let name = Self::identifier(p.as_token())?;
                    named.insert(name, ContextType::Value(val));
                }
                _ => {
                    let val = self.resolve(p).await?;
                    position.push(val);
                }
            }
        }
        named.insert(
            FC_ANON_ARGS.to_owned(),
            ContextType::Value(NaslValue::Array(position)),
        );
        self.register_mut().create_root_child(named);
        let result = match self.ctxconfigs.nasl_fn_execute(name, self.register()).await {
            Some(r) => {
                if let Ok(NaslValue::Fork(mut x)) = r {
                    Ok(if let Some(r) = x.pop() {
                        // this is a proposal for the case that the caller is immediately executing
                        // if not the position needs to be reset
                        if self.index == 0 {
                            let position = self.position().current_init_statement();
                            for i in x {
                                tracing::trace!(return_value=?i, return_position=?self.position(), interpreter_position=?position, "creating interpreter instance" );
                                self.run_specific.push(RunSpecific {
                                    register: self.register().clone(),
                                    position: position.clone(),
                                    skip_until_return: Some((self.position().clone(), i)),
                                });
                            }
                        } else {
                            tracing::trace!(
                                index = self.index,
                                "we only allow expanding of executions (fork) on root instance"
                            );
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
                    .register()
                    .named(name)
                    .ok_or_else(|| InterpretError::not_found(name))?
                    .clone();
                match found {
                    ContextType::Function(params, stmt) => {
                        // prepare default values
                        for p in params {
                            match self.register().named(&p) {
                                None => {
                                    // add default NaslValue::Null for each defined params
                                    self.register_mut()
                                        .add_local(&p, ContextType::Value(NaslValue::Null));
                                }
                                Some(_) => {}
                            }
                        }
                        match self.resolve(&stmt).await? {
                            NaslValue::Return(x) => Ok(*x),
                            a => Ok(a),
                        }
                    }
                    ContextType::Value(_) => Err(InterpretError::expected_function()),
                }
            }
        };
        self.register_mut().drop_last();
        result
    }
}

#[cfg(test)]
mod tests {
    use crate::nasl::test_prelude::*;

    #[test]
    fn default_null_on_user_defined_functions() {
        let mut t = TestBuilder::default();
        t.run(
            "function test(a, b) {
            return a + b;
        }",
        );
        t.ok("test(a: 1, b: 2);", 3);
        t.ok("test(a: 1);", 1);
        t.ok("test();", 0);
    }
}
