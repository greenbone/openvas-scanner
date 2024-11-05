// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, string::String};

    use crate::nasl::interpreter::CodeInterpreter;
    use crate::nasl::{syntax::LoadError, Loader};

    use crate::nasl::{nasl_std_functions, prelude::*};
    use crate::storage::DefaultDispatcher;

    struct FakeInclude {
        plugins: HashMap<String, String>,
    }

    impl Loader for FakeInclude {
        fn load(&self, key: &str) -> Result<String, LoadError> {
            self.plugins
                .get(key)
                .cloned()
                .ok_or_else(|| LoadError::NotFound(String::default()))
        }
        fn root_path(&self) -> Result<String, LoadError> {
            Ok(String::default())
        }
    }

    #[tokio::test]
    async fn function_variable() {
        let example = r#"
        a = 12;
        function test() {
            b['hello'] = 'world';
            return b;
        }
        "#
        .to_string();
        let plugins = HashMap::from([("example.inc".to_string(), example)]);
        let loader = FakeInclude { plugins };
        let code = r#"
        include("example.inc");
        a;
        test();
        "#;
        let register = Register::default();
        let context = ContextFactory {
            loader,
            functions: nasl_std_functions(),
            storage: DefaultDispatcher::default(),
        };
        let ctx = context.build(Default::default());
        let mut interpreter = CodeInterpreter::new(code, register, &ctx);
        assert_eq!(
            interpreter.next_statement().await.unwrap().unwrap(),
            NaslValue::Null
        );
        assert_eq!(
            interpreter.next_statement().await.unwrap().unwrap(),
            12.into()
        );
        assert_eq!(
            interpreter.next_statement().await.unwrap().unwrap(),
            NaslValue::Dict(HashMap::from([(
                "hello".to_owned(),
                NaslValue::Data("world".as_bytes().into())
            )]))
        );
    }
}
