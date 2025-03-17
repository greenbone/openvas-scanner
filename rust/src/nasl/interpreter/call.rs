// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::HashMap;

use super::interpreter::{InterpretResult, Interpreter};
use crate::nasl::{
    ContextType, NaslValue,
    interpreter::{FunctionCallError, InterpretError, InterpretErrorKind},
    syntax::{Statement, StatementKind},
    utils::lookup_keys::FC_ANON_ARGS,
};

enum ArgumentKind {
    Named(String),
    Positional,
}

impl Interpreter<'_, '_> {
    async fn resolve_argument(
        &mut self,
        arg: &Statement,
    ) -> Result<(ArgumentKind, NaslValue), InterpretError> {
        match arg.kind() {
            StatementKind::NamedParameter(val) => {
                let name = arg.as_token().identifier()?;
                let val = self.resolve(val).await?;
                Ok((ArgumentKind::Named(name), val))
            }
            _ => {
                let val = self.resolve(arg).await?;
                Ok((ArgumentKind::Positional, val))
            }
        }
    }

    async fn create_arguments_map(
        &mut self,
        args: &[Statement],
    ) -> Result<HashMap<String, ContextType>, InterpretError> {
        let mut positional = vec![];
        let mut named = HashMap::new();
        for arg in args.iter() {
            let (kind, value) = self.resolve_argument(arg).await?;
            match kind {
                ArgumentKind::Positional => {
                    positional.push(value);
                }
                ArgumentKind::Named(name) => {
                    named.insert(name, value.into());
                }
            }
        }
        named.insert(
            FC_ANON_ARGS.to_owned(),
            ContextType::Value(NaslValue::Array(positional)),
        );
        Ok(named)
    }

    async fn execute_user_defined_fn(&mut self, fn_name: &str) -> InterpretResult {
        let found = self
            .register
            .named(fn_name)
            .ok_or_else(|| InterpretError::not_found(fn_name))?
            .clone();
        match found {
            ContextType::Function(arguments, stmt) => {
                for arg in arguments {
                    if self.register.named(&arg).is_none() {
                        // Add default NaslValue::Null for each defined argument
                        self.register
                            .add_local(&arg, ContextType::Value(NaslValue::Null));
                    }
                }
                match self.resolve(&stmt).await? {
                    NaslValue::Return(x) => Ok(*x),
                    _ => Ok(NaslValue::Null),
                }
            }
            ContextType::Value(_) => Err(InterpretError::expected_function()),
        }
    }

    async fn execute_builtin_fn(
        &mut self,
        statement: &Statement,
        fn_name: &str,
    ) -> Option<InterpretResult> {
        self.context
            .execute_builtin_fn(fn_name, &self.register)
            .await
            .map(|o| {
                o.map_err(|e| {
                    InterpretError::new(
                        InterpretErrorKind::FunctionCallError(FunctionCallError::new(fn_name, e)),
                        Some(statement.clone()),
                    )
                })
            })
    }

    pub async fn call(
        &mut self,
        statement: &Statement,
        arguments: &[Statement],
    ) -> InterpretResult {
        if let Some(val) = self.fork_reentry_data.try_restore(statement.as_token())? {
            return Ok(val);
        }
        let fn_name = statement.as_token().identifier()?;
        let arguments = self.create_arguments_map(arguments).await?;
        self.register.create_root_child(arguments);
        let val = match self.execute_builtin_fn(statement, &fn_name).await {
            Some(result) => result,
            _ => self.execute_user_defined_fn(&fn_name).await,
        }?;
        self.register.drop_last();
        let val = replace_empty_or_identity_fork(val);
        self.fork_reentry_data
            .try_collect(val.clone(), statement.as_token());
        Ok(val)
    }
}

fn replace_empty_or_identity_fork(mut val: NaslValue) -> NaslValue {
    if let NaslValue::Fork(ref mut x) = val {
        if x.is_empty() {
            return NaslValue::Null;
        }
        if x.len() == 1 {
            return x.remove(0);
        }
    }
    val
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
            // r#"
            // set_kb_item(name: "port", value: 1);
            // set_kb_item(name: "port", value: 2);
            // set_kb_item(name: "host", value: "a");
            // set_kb_item(name: "host", value: "b");
            // get_kb_item("port");
            // get_kb_item("host");
            // "#,
            r#"
            set_kb_item(name: "port", value: 1);
            set_kb_item(name: "port", value: 2);
            set_kb_item(name: "host", value: "a");
            set_kb_item(name: "host", value: "b");
            get_kb_item("port");
            get_kb_item("host");
            "#,
        );

        let results = t.results();
        assert_eq!(results.len(), 10);

        let results: Vec<_> = results.into_iter().skip(4).filter_map(|x| x.ok()).collect();

        assert_eq!(
            results,
            vec![
                1.into(),
                2.into(),
                "a".into(),
                "b".into(),
                "a".into(),
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
            vec!["1:a".into(), "1:b".into(), "2:a".into(), "2:b".into(),]
        );
    }
}
