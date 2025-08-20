// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use codespan_reporting::files::SimpleFile;

use crate::nasl::error::emit_errors_str;
use crate::nasl::{NaslResult, test_utils::TestBuilder};

mod control_flow;
mod description;
mod local_var;
mod retry;

pub fn interpret(code: &str) -> Vec<NaslResult> {
    let mut t = TestBuilder::default();
    t.run_all(code);
    t.results()
}

fn interpret_err(file_name: &str, code: &str) -> String {
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
        std::iter::once(&err),
    )
}

#[macro_export]
macro_rules! interpreter_test_ok {
    ($name: ident, $code: literal, $($expected: expr),* $(,)?) => {
        #[test]
        fn $name() {
            let mut results = $crate::nasl::interpreter::tests::interpret($code);
            let mut count = 0;
            $(
                count += 1;
                let result = results.remove(0).unwrap();
                let expected = $expected.to_nasl_result().unwrap();
                assert_eq!(expected, result, "mismatch in result #{count}. Expected: {expected:?}, found {result:?}.");
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
            insta::assert_snapshot!($crate::nasl::interpreter::tests::interpret_err(
                stringify!($name),
                $code
            ));
        }
    };
}

mod operator {
    use crate::interpreter_test_ok;
    use crate::nasl::test_prelude::*;

    interpreter_test_ok!(numeric_plus, "1 + 2;", 3);
    interpreter_test_ok!(cast_to_string_middle_plus, "1+\"\"+2;", "12");
    interpreter_test_ok!(cast_to_string_end_plus, "1+2+\"\";", "3");
    interpreter_test_ok!(cast_to_string_end_plus_4, "1+2+\"\" + 4;", "34");
    interpreter_test_ok!(cast_to_string_minus, "11-\"1\";", "1");
    interpreter_test_ok!(string_plus, "\"hello \" + \"world!\";", "hello world!");
    interpreter_test_ok!(string_minus, "\"hello \" - 'o ';", "hell");
    interpreter_test_ok!(data_plus, "'hello ' + 'world!';", "hello world!".as_bytes());
    interpreter_test_ok!(data_minus, "'hello ' - 'o ';", "hell".as_bytes());

    interpreter_test_ok!(cast_to_data_middle_plus, "1+''+2;", "12".as_bytes());
    interpreter_test_ok!(cast_to_data_end_plus, "1+2+'';", "3".as_bytes());
    interpreter_test_ok!(cast_to_data_end_plus_4, "1+2+'' + 4;", "34".as_bytes());
    interpreter_test_ok!(cast_to_data_minus, "11-'1';", "1".as_bytes());
    interpreter_test_ok!(numeric_minus, "1 - 2;", -1);
    interpreter_test_ok!(multiplication, "1*2;", 2);
    interpreter_test_ok!(division, "512/2;", 256);
    interpreter_test_ok!(modulo, "512%2;", 0);
    interpreter_test_ok!(left_shift, "512 << 2;", 2048);
    interpreter_test_ok!(right_shift, "512 >> 2;", 128);
    interpreter_test_ok!(unsigned_right_shift, "-2 >>> 2;", 1073741823);
    interpreter_test_ok!(and, "-2 & 2;", 2);
    interpreter_test_ok!(or, "-2 | 2;", -2);
    interpreter_test_ok!(xor, "-2 ^ 2;", -4);
    interpreter_test_ok!(pow, "2 ** 2;", 4);
    interpreter_test_ok!(not, "~2;", -3);
    interpreter_test_ok!(r_match, "'hello' =~ 'hell';", true);
    interpreter_test_ok!(r_not_match, "'hello' !~ 'hell';", false);
    interpreter_test_ok!(contains, "'hello' >< 'hell';", true);
    interpreter_test_ok!(not_contains, "'hello' >!< 'hell';", false);
    interpreter_test_ok!(bool_not, "!23;", false);
    interpreter_test_ok!(bool_not_reverse, "!0;", true);
    interpreter_test_ok!(bool_and, "1 && 1;", true);
    interpreter_test_ok!(bool_or, "1 || 0;", true);
    interpreter_test_ok!(equals_data, "'1' == '1';", true);
    interpreter_test_ok!(equals_data_unequal, "'1' == '2';", false);
    interpreter_test_ok!(equals_string, "\"1\" == \"1\";", true);
    interpreter_test_ok!(equals_string_unequal, "\"1\" == \"2\";", false);
    interpreter_test_ok!(equals_number, "1 != 1;", false);
    interpreter_test_ok!(not_equals_data, "'1' != '1';", false);
    interpreter_test_ok!(not_equals_data_unequal, "'1' != '2';", true);
    interpreter_test_ok!(not_equals_string, "\"1\" != \"1\";", false);
    interpreter_test_ok!(not_equals_string_unequal, "\"1\" != \"2\";", true);
    interpreter_test_ok!(not_equals_number, "1 != 1;", false);
    interpreter_test_ok!(greater, "1 > 0;", true);
    interpreter_test_ok!(greater2, "1 < 0;", false);
    interpreter_test_ok!(less, "1 < 2;", true);
    interpreter_test_ok!(less2, "1 < 0;", false);
    interpreter_test_ok!(greater_equal, "1 >= 1;", true);
    interpreter_test_ok!(greater_equal_2, "1 >= 2;", false);
    interpreter_test_ok!(less_equal, "1 <= 1;", true);
    interpreter_test_ok!(less_equal2, "1 <= 0;", false);

    interpreter_test_ok!(
        x_gonna_give_it_to_ya,
        "
            a = 0;
            function test() {
                a++;
                return \"foo\";
            }
            test('hi') x 5;
            a;
        ",
        0,
        NaslValue::Null,
        "foo",
        5,
    );
}

use crate::nasl::test_prelude::*;

interpreter_test_ok!(block, "{ 3; 4; }", NaslValue::Null);
interpreter_test_ok!(
    block_scope,
    "a = 1; b = 2; { local_var a; a = 3; b = 4; } a; b;",
    1,
    2,
    NaslValue::Null,
    1,
    4,
);

interpreter_test_ok!(
    array_boolean,
    "a = 1; if ([]) { a = 2; }; a;",
    1,
    NaslValue::Null,
    NaslValue::Null,
    2
);

interpreter_test_ok!(
    null_boolean,
    "a = 1; if (b) { a = 2; }; a;",
    1,
    NaslValue::Null,
    NaslValue::Null,
    1
);

interpreter_test_ok!(
    integer_boolean,
    "a = 1; if (a) { a = 2; }; a;",
    1,
    NaslValue::Null,
    NaslValue::Null,
    2
);

interpreter_test_ok!(
    integer_boolean_zero,
    "a = 0; if (a) { a = 2; }; a;",
    0,
    NaslValue::Null,
    NaslValue::Null,
    0
);

interpreter_test_ok!(
    string_boolean,
    "a = \"foo\"; if (a) { a = 2; }; a;",
    "foo",
    NaslValue::Null,
    NaslValue::Null,
    2
);

interpreter_test_ok!(
    string_boolean_empty,
    "a = \"\"; if (a) { a = 2; }; a;",
    "",
    NaslValue::Null,
    NaslValue::Null,
    "",
);

interpreter_test_ok!(
    string_boolean_zero,
    "a = \"0\"; if (a) { a = 2; }; a;",
    "0",
    NaslValue::Null,
    NaslValue::Null,
    "0",
);

interpreter_test_ok!(
    non_int_array_index,
    "a = [1, 2, 3]; a['hello'];",
    NaslValue::Array(vec![1.into(), 2.into(), 3.into()]),
    NaslValue::Null,
);

interpreter_test_err!(nonexistent_variable, "a += 12;");

interpreter_test_err!(function_instead_of_variable, "function foo() { } a = foo;");
interpreter_test_err!(variable_instead_of_function, "foo = 3; foo();");

interpreter_test_err!(invalid_regex, r#"a = "hello world"; a =~ "[";"#);

interpreter_test_err!(undefined_fn, "foo();");

interpreter_test_err!(expected_str, "a =~ 5;");
interpreter_test_err!(expected_array, "a = 5; a[3];");

interpreter_test_err!(array_out_of_range, "a = [1, 2, 3]; a[3];");
interpreter_test_err!(negative_array_index, "a = [1, 2, 3]; a[-3];");
