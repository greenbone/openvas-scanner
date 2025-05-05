// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use codespan_reporting::files::SimpleFile;

use crate::nasl::error::emit_errors_str;
use crate::nasl::{NaslResult, test_utils::TestBuilder};

mod description;
mod local_var;
mod retry;

pub fn interpret(code: &str) -> Vec<NaslResult> {
    let mut t = TestBuilder::default();
    t.run_all(code);
    t.results()
}

pub fn interpret_err(file_name: &str, code: &str) -> String {
    let mut t = TestBuilder::default();
    t.run_all(code);
    let err = t
        .interpreter_results()
        .into_iter()
        .find(|result| result.is_err())
        .unwrap()
        .unwrap_err();
    emit_errors_str(
        &SimpleFile::new(file_name.to_string(), code.to_string()),
        vec![err].into_iter(),
    )
}

#[macro_export]
macro_rules! interpreter_test_single {
    ($name: ident, $code: literal, $expected: expr) => {
        #[test]
        fn $name() {
            let mut results = crate::nasl::interpreter::tests::interpret($code);
            assert_eq!(results.len(), 1);
            let result = results.remove(0).unwrap();
            assert_eq!(result, $expected.to_nasl_result().unwrap());
        }
    };
}

#[macro_export]
macro_rules! interpreter_test {
    ($name: ident, $code: literal, $($expected: expr),* $(,)?) => {
        #[test]
        fn $name() {
            let mut results = crate::nasl::interpreter::tests::interpret($code);
            $(
                let result = results.remove(0).unwrap();
                assert_eq!(result, $expected.to_nasl_result().unwrap());
            )*
            assert_eq!(results.len(), 0);
        }
    };
}

#[macro_export]
macro_rules! interpreter_test_err {
    ($name: ident, $code: literal) => {
        #[test]
        fn $name() {
            insta::assert_snapshot!(crate::nasl::interpreter::tests::interpret_err(
                stringify!($name),
                $code
            ));
        }
    };
}

mod operator {
    use crate::interpreter_test_single;
    use crate::nasl::test_prelude::*;

    interpreter_test_single!(numeric_plus, "1 + 2;", 3);
    interpreter_test_single!(cast_to_string_middle_plus, "1+\"\"+2;", "12");
    interpreter_test_single!(cast_to_string_end_plus, "1+2+\"\";", "3");
    interpreter_test_single!(cast_to_string_end_plus_4, "1+2+\"\" + 4;", "34");
    interpreter_test_single!(cast_to_string_minus, "11-\"1\";", "1");
    interpreter_test_single!(string_plus, "\"hello \" + \"world!\";", "hello world!");
    interpreter_test_single!(string_minus, "\"hello \" - 'o ';", "hell");
    interpreter_test_single!(data_plus, "'hello ' + 'world!';", "hello world!".as_bytes());
    interpreter_test_single!(data_minus, "'hello ' - 'o ';", "hell".as_bytes());

    interpreter_test_single!(cast_to_data_middle_plus, "1+''+2;", "12".as_bytes());
    interpreter_test_single!(cast_to_data_end_plus, "1+2+'';", "3".as_bytes());
    interpreter_test_single!(cast_to_data_end_plus_4, "1+2+'' + 4;", "34".as_bytes());
    interpreter_test_single!(cast_to_data_minus, "11-'1';", "1".as_bytes());
    interpreter_test_single!(numeric_minus, "1 - 2;", -1);
    interpreter_test_single!(multiplication, "1*2;", 2);
    interpreter_test_single!(division, "512/2;", 256);
    interpreter_test_single!(modulo, "512%2;", 0);
    interpreter_test_single!(left_shift, "512 << 2;", 2048);
    interpreter_test_single!(right_shift, "512 >> 2;", 128);
    interpreter_test_single!(unsigned_right_shift, "-2 >>> 2;", 1073741823);
    interpreter_test_single!(and, "-2 & 2;", 2);
    interpreter_test_single!(or, "-2 | 2;", -2);
    interpreter_test_single!(xor, "-2 ^ 2;", -4);
    interpreter_test_single!(pow, "2 ** 2;", 4);
    interpreter_test_single!(not, "~2;", -3);
    interpreter_test_single!(r_match, "'hello' =~ 'hell';", true);
    interpreter_test_single!(r_not_match, "'hello' !~ 'hell';", false);
    interpreter_test_single!(contains, "'hello' >< 'hell';", true);
    interpreter_test_single!(not_contains, "'hello' >!< 'hell';", false);
    interpreter_test_single!(bool_not, "!23;", false);
    interpreter_test_single!(bool_not_reverse, "!0;", true);
    interpreter_test_single!(bool_and, "1 && 1;", true);
    interpreter_test_single!(bool_or, "1 || 0;", true);
    interpreter_test_single!(equals_data, "'1' == '1';", true);
    interpreter_test_single!(equals_data_unequal, "'1' == '2';", false);
    interpreter_test_single!(equals_string, "\"1\" == \"1\";", true);
    interpreter_test_single!(equals_string_unequal, "\"1\" == \"2\";", false);
    interpreter_test_single!(equals_number, "1 != 1;", false);
    interpreter_test_single!(not_equals_data, "'1' != '1';", false);
    interpreter_test_single!(not_equals_data_unequal, "'1' != '2';", true);
    interpreter_test_single!(not_equals_string, "\"1\" != \"1\";", false);
    interpreter_test_single!(not_equals_string_unequal, "\"1\" != \"2\";", true);
    interpreter_test_single!(not_equals_number, "1 != 1;", false);
    interpreter_test_single!(greater, "1 > 0;", true);
    interpreter_test_single!(greater2, "1 < 0;", false);
    interpreter_test_single!(less, "1 < 2;", true);
    interpreter_test_single!(less2, "1 < 0;", false);
    interpreter_test_single!(greater_equal, "1 >= 1;", true);
    interpreter_test_single!(greater_equal_2, "1 >= 2;", false);
    interpreter_test_single!(less_equal, "1 <= 1;", true);
    interpreter_test_single!(less_equal2, "1 <= 0;", false);

    #[test]
    fn x_gonna_give_it_to_ya() {
        let mut t = TestBuilder::default();
        t.run_all("function test() { }; test('hi') x 200;");
        assert_eq!(t.results().pop().unwrap().unwrap(), NaslValue::Null);
    }
}

#[cfg(test)]
mod assign {
    use crate::nasl::test_prelude::*;
    use std::collections::HashMap;

    #[test]
    fn variables() {
        let mut t = TestBuilder::default();
        t.ok("a = 12;", 12);
        t.ok("a += 13;", 25);
        t.ok("a -= 2;", 23);
        t.ok("a /= 2;", 11);
        t.ok("a *= 2;", 22);
        t.ok("a >>= 2;", 5);
        t.ok("a <<= 2;", 20);
        t.ok("a >>>= 2;", 5);
        t.ok("a %= 2;", 1);
        t.ok("a++;", 1);
        t.ok("++a;", 3);
        t.ok("a--;", 3);
        t.ok("--a;", 1);
    }

    #[test]
    fn unsigned_shift_operator() {
        let mut t = TestBuilder::default();
        t.ok("a = -5;", -5);
        t.ok("a >>= 2;", -2);
        t.ok("a = -5;", -5);
        t.ok("a >>>= 2;", 1073741822);
    }

    interpreter_test!(basic_assign, "a = 12; a + 3;", 12, 15);

    interpreter_test!(
        implicit_extend,
        "a[2] = 12; a;",
        12,
        NaslValue::Array(vec![NaslValue::Null, NaslValue::Null, 12.into()])
    );

    interpreter_test!(
        implicit_transformation,
        "a = 12; a; a[2] = 12; a;",
        12,
        12,
        12,
        NaslValue::Array(vec![12.into(), NaslValue::Null, 12.into()])
    );

    interpreter_test!(
        dict,
        "a['hi'] = 12; a; a['hi'];",
        12,
        NaslValue::Dict(HashMap::from([("hi".to_string(), 12.into())])),
        12
    );

    interpreter_test!(array_creation, "a = [1, 2, 3];", vec![1, 2, 3]);

    #[test]
    fn multidimensional_array() {
        let mut t = TestBuilder::default();
        t.ok(
            "a = [[1,2,3], [4,5,6], [7,8,9]];",
            vec![
                NaslValue::Array(vec![
                    NaslValue::Number(1),
                    NaslValue::Number(2),
                    NaslValue::Number(3),
                ]),
                NaslValue::Array(vec![
                    NaslValue::Number(4),
                    NaslValue::Number(5),
                    NaslValue::Number(6),
                ]),
                NaslValue::Array(vec![
                    NaslValue::Number(7),
                    NaslValue::Number(8),
                    NaslValue::Number(9),
                ]),
            ],
        );
        t.ok("a[0][0];", 1);
        t.ok("a[0][1];", 2);
        t.ok("a[0][2];", 3);
        t.ok("a[1][0];", 4);
        t.ok("a[1][1];", 5);
        t.ok("a[1][2];", 6);
        t.ok("a[2][0];", 7);
        t.ok("a[2][1];", 8);
        t.ok("a[2][2];", 9);
        t.ok("a[1][2] = 1000;", 1000);
        t.ok("a[0][0];", 1);
        t.ok("a[0][1];", 2);
        t.ok("a[0][2];", 3);
        t.ok("a[1][0];", 4);
        t.ok("a[1][1];", 5);
        t.ok("a[1][2];", 1000);
        t.ok("a[2][0];", 7);
        t.ok("a[2][1];", 8);
        t.ok("a[2][2];", 9);
    }
}

mod misc {
    use crate::nasl::test_prelude::*;

    interpreter_test!(block, "{ 3; 4; }", NaslValue::Null);
    interpreter_test!(
        block_scope,
        "a = 3; { local_var a; a = 4; } a;",
        3,
        NaslValue::Null,
        4
    );

    interpreter_test_err!(nonexistent_variable, "a += 12;");
}
