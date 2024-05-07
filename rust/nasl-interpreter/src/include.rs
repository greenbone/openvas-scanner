// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::*;

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
        fn root_path(&self) -> Result<std::string::String, nasl_syntax::LoadError> {
            Ok(String::default())
        }
    }

    #[test]
    fn function_variable() {
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
        let context = ContextBuilder {
            loader: Box::new(loader),
            ..Default::default()
        };
        let ctx = context.build();
        let mut interpreter = CodeInterpreter::new(code, register, &ctx);
        assert_eq!(interpreter.next(), Some(Ok(NaslValue::Null)));
        assert_eq!(interpreter.next(), Some(Ok(12.into())));
        assert_eq!(
            interpreter.next(),
            Some(Ok(NaslValue::Dict(HashMap::from([(
                "hello".to_owned(),
                NaslValue::Data("world".as_bytes().into())
            )]))))
        );
    }
}
