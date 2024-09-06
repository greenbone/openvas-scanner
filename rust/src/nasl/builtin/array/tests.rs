// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::nasl::test_prelude::*;

    macro_rules! make_dict {
        ($($key:expr => $val:expr),*) => {
            {
                #[allow(unused_mut)]
                let mut result: HashMap<String, NaslValue> = HashMap::new();
                $(
                   let key: String = format!("{}", $key);
                   let value: NaslValue = $val.into();
                   result.insert(key, value);
                )*
                let result: NaslValue = result.into();
                result
            }
        };
    }

    #[test]
    fn make_array() {
        check_code_result("make_array(1, 0, 2, 1);", make_dict!(1 => 0i64, 2 => 1i64));
        check_code_result(
            "make_array(1, 0, 2, 1, 1);",
            make_dict!(1 => 0i64, 2 => 1i64),
        );
        check_code_result("make_array(1);", make_dict!());
        check_code_result("make_array();", make_dict!());
    }

    #[test]
    fn make_list() {
        let mut t = TestBuilder::default();
        t.ok("a = [2,4];", vec![2, 4u32]);
        t.ok("make_list(1, 0);", vec![1, 0u32]);
        t.ok("make_list();", Vec::<usize>::new());
        t.ok("make_list(1,NULL,2);", vec![1, 2u32]);
        t.run(r#"b = make_array("el", 6);"#);
        t.ok("make_list(1, 0, b);", vec![1, 0, 6u32]);
        t.ok("make_list(1, 0, a);", vec![1, 0, 2, 4u32]);
    }

    #[test]
    fn sort() {
        let mut t = TestBuilder::default();
        t.run(r#"a = make_array(5, 6, 7, 8);"#);
        t.run(r#"l = make_list("abbb", 1, "aaaa", 0, a);"#);
        t.ok(
            r#"s = sort(l);"#,
            NaslValue::Array(vec![
                NaslValue::Number(0),
                NaslValue::Number(1),
                NaslValue::Number(6),
                NaslValue::Number(8),
                NaslValue::String("aaaa".to_string()),
                NaslValue::String("abbb".to_string()),
            ]),
        );
    }

    #[test]
    fn keys() {
        let mut t = TestBuilder::default();
        t.run(r#"a = make_array("a", 6);"#);
        t.run(r#"l = make_list("foo", "bar");"#);
        t.ok(
            r#"keys(a,l);"#,
            NaslValue::Array(vec![
                NaslValue::String("a".to_string()),
                NaslValue::Number(0),
                NaslValue::Number(1),
            ]),
        );
    }

    #[test]
    fn max_index() {
        let mut t = TestBuilder::default();
        t.run(r#"l = [1,2,3,4,5];"#);
        t.ok(r#"max_index(l);"#, 5);
        t.ok(r#"max_index(make_array(1,2,3,4,5,6,7));"#, 3);
        t.ok(r#"max_index(make_list(1, 0));"#, 2);
        t.ok(r#"max_index(make_list());"#, 0);
    }
}
