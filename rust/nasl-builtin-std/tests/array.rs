// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use nasl_builtin_std::ContextBuilder;
    use nasl_builtin_utils::Register;
    use nasl_interpreter::CodeInterpreter;
    use nasl_syntax::NaslValue;
    macro_rules! make_dict {
        ($($key:expr => $val:expr),*) => {
            {
                #[allow(unused_mut)]
                let mut result: HashMap<String, nasl_syntax::NaslValue> = HashMap::new();
                $(
                   let key: String = format!("{}", $key);
                   let value: nasl_syntax::NaslValue = $val.into();
                   result.insert(key, value);
                )*
                let result: nasl_syntax::NaslValue = result.into();
                result
            }
        };
    }

    #[test]
    fn make_array() {
        let code = r###"
        make_array(1, 0, 2, 1);
        make_array(1, 0, 2, 1, 1);
        make_array(1);
        make_array();
        "###;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(parser.next(), Some(Ok(make_dict!(1 => 0i64, 2 => 1i64))));
        assert_eq!(parser.next(), Some(Ok(make_dict!(1 => 0i64, 2 => 1i64))));
        assert_eq!(parser.next(), Some(Ok(make_dict!())));
        assert_eq!(parser.next(), Some(Ok(make_dict!())));
    }

    #[test]
    fn make_list() {
        let code = r#"
        a = [2,4];
        make_list(1, 0);
        make_list();
        make_list(1,NULL,2);
        b = make_array("el", 6);
        make_list(1, 0, b);
        make_list(1, 0, a);
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Array(vec![
                NaslValue::Number(2),
                NaslValue::Number(4)
            ])))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Array(vec![
                NaslValue::Number(1),
                NaslValue::Number(0)
            ])))
        );
        assert_eq!(parser.next(), Some(Ok(NaslValue::Array([].into()))));
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Array(vec![
                NaslValue::Number(1),
                NaslValue::Number(2)
            ])))
        );
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Array(vec![
                NaslValue::Number(1),
                NaslValue::Number(0),
                NaslValue::Number(6)
            ])))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Array(vec![
                NaslValue::Number(1),
                NaslValue::Number(0),
                NaslValue::Number(2),
                NaslValue::Number(4)
            ])))
        );
    }

    #[test]
    fn sort() {
        let code = r#"
        a = make_array(5, 6, 7, 8);
        l = make_list("abbb", 1, "aaaa", 0, a);
        s = sort(l);
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        parser.next();
        let a = parser.next();
        let b = Some(Ok(NaslValue::Array(vec![
            NaslValue::Number(0),
            NaslValue::Number(1),
            NaslValue::Number(6),
            NaslValue::Number(8),
            NaslValue::String("aaaa".to_string()),
            NaslValue::String("abbb".to_string()),
        ])));
        assert_eq!(a, b);
    }

    #[test]
    fn keys() {
        let code = r#"
        a = make_array("a", 6);
        l = make_list("foo", "bar");
        keys(a,l);
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        parser.next();
        let a = parser.next();
        let b = Some(Ok(NaslValue::Array(vec![
            NaslValue::String("a".to_string()),
            NaslValue::Number(0),
            NaslValue::Number(1),
        ])));

        assert_eq!(a, b);
    }

    #[test]
    fn max_index() {
        let code = r###"
        l = [1,2,3,4,5];
        max_index(l);
        max_index(make_array(1,2,3,4,5,6,7));
        max_index(make_list(1, 0));
        max_index(make_list());
        "###;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(5))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(3))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(2))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(0))));
    }
}
