// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, string::String};

    use crate::nasl::test_utils::TestBuilder;
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

    #[test]
    fn function_variable() {
        let t = TestBuilder::default();
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
        let context = ContextFactory {
            loader,
            functions: nasl_std_functions(),
            storage: DefaultDispatcher::default(),
        };
        let mut t = t.with_context(context);
        t.run_all(code);
        let mut results = t.results();
        let mut next_result = move || results.remove(0).unwrap();
        assert_eq!(next_result(), NaslValue::Null);
        assert_eq!(next_result(), 12.into());
        assert_eq!(
            next_result(),
            NaslValue::Dict(HashMap::from([(
                "hello".to_owned(),
                NaslValue::Data("world".as_bytes().into())
            )]))
        );
    }
}
