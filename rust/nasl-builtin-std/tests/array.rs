// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use nasl_interpreter::nasl_test;
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
        nasl_test! {
             "make_array(1, 0, 2, 1);" == make_dict!(1 => 0i64, 2 => 1i64),
             "make_array(1, 0, 2, 1, 1);" == make_dict!(1 => 0i64, 2 => 1i64),
             "make_array(1);" == make_dict!(),
             "make_array();" == make_dict!(),
        }
    }

    #[test]
    fn make_list() {
        nasl_test! {
             "a = [2,4];" == vec![2, 4u32],
             "make_list(1, 0);" == vec![1, 0u32],
             "make_list();" == Vec::<usize>::new(),
             "make_list(1,NULL,2);" == vec![1, 2u32],
             r#"b = make_array("el", 6);"#,
             "make_list(1, 0, b);" == vec![1, 0, 6u32],
             "make_list(1, 0, a);" == vec![1, 0, 2, 4u32],
        }
    }

    #[test]
    fn sort() {
        nasl_test! {
            r#"a = make_array(5, 6, 7, 8);"#,
            r#"l = make_list("abbb", 1, "aaaa", 0, a);"#,
            r#"s = sort(l);"# == NaslValue::Array(vec![
                NaslValue::Number(0),
                NaslValue::Number(1),
                NaslValue::Number(6),
                NaslValue::Number(8),
                NaslValue::String("aaaa".to_string()),
                NaslValue::String("abbb".to_string()),
            ]),
        }
    }

    #[test]
    fn keys() {
        nasl_test! {
            r#"a = make_array("a", 6);"#,
            r#"l = make_list("foo", "bar");"#,
            r#"keys(a,l);"# == NaslValue::Array(vec![
                NaslValue::String("a".to_string()),
                NaslValue::Number(0),
                NaslValue::Number(1),
            ]),
        }
    }

    #[test]
    fn max_index() {
        nasl_test! {
            r#"l = [1,2,3,4,5];"#,
            r#"max_index(l);"# == 5,
            r#"max_index(make_array(1,2,3,4,5,6,7));"# == 3,
            r#"max_index(make_list(1, 0));"# == 2,
            r#"max_index(make_list());"# == 0,
        }
    }
}
