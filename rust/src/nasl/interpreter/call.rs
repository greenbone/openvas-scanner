// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::nasl::syntax::{Statement, StatementKind::*};
use crate::nasl::utils::lookup_keys::FC_ANON_ARGS;

use crate::nasl::interpreter::{
    error::{FunctionCallError, InterpretError},
    interpreter::{InterpretResult, RunSpecific},
    Interpreter,
};

use crate::nasl::syntax::NaslValue;
use crate::nasl::utils::ContextType;
use std::collections::HashMap;

use super::InterpretErrorKind;

impl Interpreter<'_> {
    pub async fn call(
        &mut self,
        statement: &Statement,
        arguments: &[Statement],
    ) -> InterpretResult {
        let name = statement.as_token();
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
            Some(Ok(NaslValue::Fork(x))) if self.index == 0 && !x.is_empty() => {
                let mut additional = Vec::with_capacity(x.len() - 1);
                let root_pos = self.run_specific[0].position.clone();

                for (vi, v) in x.iter().enumerate() {
                    for (rsi, rs) in self.run_specific.iter_mut().enumerate() {
                        let mut pos = root_pos.clone();
                        // needs to be reduced because a previous down statement enhanced the number
                        pos.reduce_last();

                        if vi == 0 {
                            rs.skip_until_return.push((pos, v.clone()));
                        } else {
                            let position = pos.current_init_statement();
                            let mut skip_until_return = rs
                                .skip_until_return
                                .iter()
                                .filter(|(p, _)| p != &pos)
                                .cloned()
                                .collect::<Vec<_>>();
                            skip_until_return.push((pos.clone(), v.clone()));
                            tracing::trace!(run_specific_index=rsi, value_index=vi, value=?v, ?pos, ?skip_until_return, ?rs.skip_until_return, "new fork");

                            additional.push(RunSpecific {
                                register: rs.register.clone(),
                                position: position.clone(),
                                skip_until_return,
                            });
                        }
                    }
                }
                self.run_specific.extend(additional);
                Ok(x[0].clone())
            }

            Some(Ok(NaslValue::Fork(x))) if self.index == 0 && x.is_empty() => Ok(NaslValue::Null),

            Some(Ok(NaslValue::Fork(_))) => {
                unreachable!("NaslValue::Fork must only occur on root instance, all other cases should return a value within run_specific")
            }
            Some(r) => r.map_err(|e| {
                InterpretError::new(
                    InterpretErrorKind::FunctionCallError(FunctionCallError::new(name, e)),
                    Some(statement.clone()),
                )
            }),
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
                            if self.register().named(&p).is_none() {
                                // add default NaslValue::Null for each defined params
                                self.register_mut()
                                    .add_local(&p, ContextType::Value(NaslValue::Null));
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

    #[test]
    #[tracing_test::traced_test]
    fn multiple_forks() {
        let mut t = TestBuilder::default();
        t.run_all(
            r#"
set_kb_item(name: "port", value: 1);
set_kb_item(name: "port", value: 2);
set_kb_item(name: "host", value: "a");
set_kb_item(name: "host", value: "b");
get_kb_item("port");
get_kb_item("host");
"#,
        );

        assert_eq!(t.results().len(), 10);
        let results: Vec<_> = t
            .results()
            .into_iter()
            .skip(4)
            // .filter_map(|x| x.ok())
            .map(|x| x.unwrap())
            .collect();

        assert_eq!(
            results,
            vec![
                1.into(),
                2.into(),
                "a".into(),
                "a".into(),
                "b".into(),
                "b".into(),
            ]
        );
    }
    #[test]
    #[tracing_test::traced_test]
    fn empty_fork() {
        let mut t = TestBuilder::default();
        t.run_all(
            r#"
get_kb_item("port") + ":" + get_kb_item("host");
"#,
        );

        let results: Vec<_> = t.results().into_iter().filter_map(|x| x.ok()).collect();

        assert_eq!(results, vec!["\0:\0".into()]);
    }

    #[test]
    #[tracing_test::traced_test]
    fn multiple_forks_on_one_line() {
        let mut t = TestBuilder::default();
        t.run_all(
            r#"
set_kb_item(name: "port", value: 1);
set_kb_item(name: "port", value: 2);
set_kb_item(name: "host", value: "a");
set_kb_item(name: "host", value: "b");
get_kb_item("port") + ":" + get_kb_item("host");
"#,
        );

        let results: Vec<_> = t
            .results()
            .into_iter()
            .skip(4)
            .filter_map(|x| x.ok())
            .collect();

        assert_eq!(
            results,
            vec!["1:a".into(), "2:a".into(), "1:b".into(), "2:b".into(),]
        );
    }
}
