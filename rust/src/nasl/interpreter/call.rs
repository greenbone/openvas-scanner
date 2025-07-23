// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::HashMap;

use super::{Interpreter, Result, nasl_value::RuntimeValue};
use crate::nasl::{
    NaslValue,
    error::Spanned,
    interpreter::FunctionCallError,
    syntax::{
        Ident,
        grammar::{FnArg, FnCall},
    },
    utils::lookup_keys::FC_ANON_ARGS,
};

use crate::nasl::interpreter::InterpreterError as Error;
use crate::nasl::interpreter::InterpreterErrorKind as ErrorKind;

enum ArgumentKind {
    Named(String),
    Positional,
}

impl Interpreter<'_> {
    async fn resolve_arg(&mut self, arg: &FnArg) -> Result<(ArgumentKind, NaslValue), Error> {
        match arg {
            FnArg::Anonymous(anon) => {
                let val = self.resolve_expr(&anon.expr).await?;
                Ok((ArgumentKind::Positional, val))
            }
            FnArg::Named(named) => {
                let val = self.resolve_expr(&named.expr).await?;
                Ok((ArgumentKind::Named(named.ident.to_string()), val))
            }
        }
    }

    async fn create_arguments_map(
        &mut self,
        args: &[FnArg],
    ) -> Result<HashMap<String, RuntimeValue>, Error> {
        let mut positional = vec![];
        let mut named = HashMap::new();
        for arg in args.iter() {
            let (kind, value) = self.resolve_arg(arg).await?;
            match kind {
                ArgumentKind::Positional => {
                    positional.push(value);
                }
                ArgumentKind::Named(name) => {
                    named.insert(name, RuntimeValue::Value(value));
                }
            }
        }
        named.insert(
            FC_ANON_ARGS.to_owned(),
            RuntimeValue::Value(NaslValue::Array(positional)),
        );
        Ok(named)
    }

    async fn execute_user_defined_fn(&mut self, fn_name: &Ident) -> Result {
        let found = self
            .register
            .named(fn_name.to_str())
            .ok_or_else(|| {
                ErrorKind::UndefinedFunction(fn_name.to_str().to_owned()).with_span(&fn_name)
            })?
            .clone();
        match found {
            RuntimeValue::Function(arguments, stmt) => {
                for arg in arguments {
                    if self.register.named(&arg).is_none() {
                        // Add default NaslValue::Null for each defined argument
                        self.register
                            .add_local(&arg, RuntimeValue::Value(NaslValue::Null));
                    }
                }
                match self.resolve_block(&stmt).await? {
                    NaslValue::Return(x) => Ok(*x),
                    _ => Ok(NaslValue::Null),
                }
            }
            RuntimeValue::Value(_) => Err(ErrorKind::ValueExpectedFunction.with_span(fn_name)),
        }
    }

    async fn execute_builtin_fn(&mut self, call: &FnCall) -> Option<Result> {
        self.scan_ctx
            .execute_builtin_fn(call.fn_name.to_str(), &self.register, &mut self.script_ctx)
            .await
            .map(|o| {
                o.map_err(|e| {
                    Error::new(
                        ErrorKind::FunctionCallError(FunctionCallError::new(
                            call.fn_name.to_str(),
                            e,
                        )),
                        call.fn_name.span(),
                    )
                })
            })
    }

    pub(crate) async fn resolve_fn_call(&mut self, call: &FnCall) -> Result {
        let num_repeats = if let Some(ref num_repeats) = call.num_repeats {
            self.resolve_expr(num_repeats)
                .await?
                .as_number()
                .map_err(|e| e.with_span(&**num_repeats))?
        } else {
            1
        };
        let mut val = NaslValue::Null;
        for _ in 0..num_repeats {
            let span = call.fn_name.span();
            if let Some(val) = self.fork_reentry_data.try_restore(&span)? {
                return Ok(val);
            }
            let arguments = self.create_arguments_map(call.args.as_ref()).await?;
            self.register.create_global_child(arguments);
            val = match self.execute_builtin_fn(call).await {
                Some(result) => result,
                _ => self.execute_user_defined_fn(&call.fn_name).await,
            }?;
            self.register.drop_last();
            val = replace_empty_or_identity_fork(val);
            self.fork_reentry_data.try_collect(val.clone(), &span);
        }
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
