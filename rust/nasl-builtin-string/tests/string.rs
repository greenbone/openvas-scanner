// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception
#[cfg(test)]
mod tests {
    use nasl_builtin_utils::function::ToNaslResult;
    use nasl_interpreter::*;
    use FunctionErrorKind::*;
    use NaslValue::*;

    fn check_line_of_code(code: &str, f: impl Fn(Result<NaslValue, InterpretError>)) {
        let register = Register::default();
        let binding = ContextFactory::default();
        let context = binding.build(Default::default(), Default::default());
        let mut parser = CodeInterpreter::new(code, register, &context);
        f(parser.next().unwrap())
    }

    fn check_err(code: &str, f: impl Fn(FunctionErrorKind) -> bool) {
        check_line_of_code(code, |val| {
            let val = val.unwrap_err();
            match val.kind {
                InterpretErrorKind::FunctionCallError(err) => {
                    assert!(f(err.kind));
                }
                _ => panic!("Function did not return expected error."),
            }
        });
    }

    fn check_ok(code: &str, expected: impl ToNaslResult) {
        let expected = expected.to_nasl_result().unwrap();
        check_line_of_code(code, |val| {
            let val = val.unwrap();
            assert_eq!(val, expected);
        });
    }

    fn check_multiple(code: &str, expected: Vec<NaslValue>) {
        let register = Register::default();
        let binding = ContextFactory::default();
        let context = binding.build(Default::default(), Default::default());
        let parser = CodeInterpreter::new(code, register, &context);
        for (val, expected) in parser.zip(expected.into_iter()) {
            assert_eq!(val, Ok(expected));
        }
    }

    #[test]
    fn hexstr() {
        check_ok("hexstr('foo');", "666f6f");
        check_ok("hexstr('foo', 'I will be ignored');", "666f6f");
        check_ok("hexstr(6);", Null);
        check_ok("hexstr();", Null);
        check_ok("hexstr(raw_string(10, 208, 102, 165, 210, 159, 63, 42, 42, 28, 124, 23, 221, 8, 42, 121));", "0ad066a5d29f3f2a2a1c7c17dd082a79");
    }

    #[test]
    fn raw_string() {
        check_ok("raw_string(0x7B);", vec![123]);
        check_ok("raw_string(0x7B, 1);", vec![123, 1]);
        check_ok(
            "raw_string(0x7B, 1, 'Hallo');",
            vec![123, 1, 72, 97, 108, 108, 111],
        );
    }

    #[test]
    fn tolower() {
        check_ok("tolower(0x7B);", Null);
        check_ok("tolower('HALLO');", "hallo");
    }

    #[test]
    fn toupper() {
        check_ok("toupper(0x7B);", Null);
        check_ok("toupper('hallo');", "HALLO");
        check_ok("toupper();", Null);
    }

    #[test]
    fn strlen() {
        check_ok("strlen(0x7B);", 0i64);
        check_ok("strlen('hallo');", 5i64);
    }

    #[test]
    fn string() {
        check_ok("string(0x7B);", "123");
        check_ok("string(0x7B, 1);", "1231");
        check_ok("string(0x7B, 1, 'Hallo');", "1231Hallo");
        check_ok("string(0x7B, 1, NULL, 'Hallo');", "1231Hallo");
    }

    #[test]
    fn substr() {
        check_ok("substr('hello', 1);", "ello");
        check_ok("substr('hello', 0, 4);", "hell");
        check_ok("substr('hello', 6);", Null);
    }

    #[test]
    fn crap() {
        check_ok("crap(5);", "XXXXX");
        check_ok("crap(length: 5);", "XXXXX");
        check_ok(r#"crap(data: "ab", length: 5);"#, "ababababab");
    }

    #[test]
    fn chomp() {
        check_ok("chomp('abc');", "abc");
        check_ok("chomp('abc\n');", "abc");
        check_ok("chomp('abc  ');", "abc");
        check_ok("chomp('abc\n\t\r ');", "abc");
        check_err("chomp();", |err| {
            matches!(err, MissingPositionalArguments { .. })
        });
    }

    #[test]
    fn stridx() {
        check_ok(r#"stridx("abc", "bcd");"#, -1);
        check_ok(r#"stridx("abc", "bc");"#, 1);
        check_ok(r#"stridx("abc", "abc");"#, 0);
        check_ok(r#"stridx("blahabc", "abc", 4);"#, 0);
        check_ok(r#"stridx("blahabc", "abc", 3);"#, 1);
        check_ok(r#"stridx("blahbc", "abc", 2);"#, -1);
    }

    #[test]
    fn display() {
        check_ok("display('abc');", Null);
        check_ok(r#"display("abc");"#, Null);
    }

    #[test]
    fn hexstr_to_data() {
        let code = r#"
        a = hexstr_to_data("4bb3c4a4f893ad8c9bdc833c325d62b3");
        data_to_hexstr(a);
        "#;
        check_multiple(
            code,
            vec![
                Data(vec![
                    75, 179, 196, 164, 248, 147, 173, 140, 155, 220, 131, 60, 50, 93, 98, 179,
                ]),
                String("4bb3c4a4f893ad8c9bdc833c325d62b3".to_string()),
            ],
        );
    }

    #[test]
    fn ord() {
        check_ok(r#"ord("a");"#, 97);
        check_ok(r#"ord("b");"#, 98);
        check_ok(r#"ord("c");"#, 99);
        check_ok(r#"ord("");"#, Null);
        check_err("ord(1);", |err| matches!(err, WrongArgument { .. }));
        check_err("ord();", |err| {
            matches!(err, MissingPositionalArguments { .. })
        });
    }

    #[test]
    fn match_() {
        check_ok(r#"match(string: "abcd", pattern: "*cd");"#, true);
        check_ok(r#"match(string: "abcd", pattern: "*CD");"#, false);
        check_ok(
            r#"match(string: "abcd", pattern: "*CD", icase: FALSE);"#,
            false,
        );
        check_ok(
            r#"match(string: "abcd", pattern: "*CD", icase: TRUE);"#,
            true,
        );
        // g_pattern_spec allows globs to match slashes, make sure we do too
        check_ok(r#"match(string: "a///", pattern: "a*");"#, true);
        check_ok(r#"match(string: "///a", pattern: "*a");"#, true);
        check_err(r#"match(string: "abcd");"#, |err| {
            matches!(err, MissingArguments { .. })
        });
        check_err(r#"match(pattern: "ab");"#, |err| {
            matches!(err, MissingArguments { .. })
        });
    }

    #[test]
    fn hex() {
        check_ok(r#"hex(0);"#, "0x00");
        check_ok(r#"hex(32);"#, "0x20");
        check_ok(r#"hex(255);"#, "0xff");
        check_ok(r#"hex(256);"#, "0x00");
        check_ok(r#"hex(257);"#, "0x01");
        check_ok(r#"hex(-2);"#, "0xfe");
        check_err(r#"hex();"#, |err| {
            matches!(err, MissingPositionalArguments { .. })
        });
    }

    #[test]
    fn insstr() {
        check_ok(r#"insstr("foo bar", "rab", 4);"#, "foo rab");
        check_ok(r#"insstr("foo bar", "rab", 4, 100);"#, "foo rab");
        check_err(r#"insstr("foo bar", "rab", 4, 0);"#, |err| {
            matches!(err, WrongArgument { .. })
        });
    }

    #[test]
    fn int() {
        check_ok(r#"int("123");"#, 123);
        check_ok(r#"int(123);"#, 123);
        check_ok(r#"int("123x");"#, 123);
        check_ok(r#"int("123xx");"#, 0);
        check_ok(r#"int(TRUE);"#, 1);
    }

    #[test]
    fn split() {
        check_ok(
            r#"split("a\nb\nc");"#,
            vec!["a\n".to_string(), "b\n".to_string(), "c".to_string()],
        );
        check_ok(
            r#"split("a\nb\nc", keep: FALSE);"#,
            vec!["a".to_string(), "b".to_string(), "c".to_string()],
        );
        check_ok(
            r#"split("a;b;c", sep: ";");"#,
            vec!["a;".to_string(), "b;".to_string(), "c".to_string()],
        );
        check_err(r#"split();"#, |err| {
            matches!(err, MissingPositionalArguments { .. })
        });
    }

    #[test]
    fn replace() {
        check_ok(
            r#"replace(string: "abc", find: "b", replace: "foo");"#,
            "afooc",
        );
        check_err(r#"replace();"#, |err| {
            matches!(err, MissingArguments { .. })
        });
        check_err(r#"replace(string: "abc");"#, |err| {
            matches!(err, MissingArguments { .. })
        });
        check_ok(r#"replace(string: "abc", find: "b");"#, "ac");
        check_ok(r#"replace(string: "abcbd", find: "b", count: 1);"#, "acbd");
    }

    #[test]
    fn strstr() {
        check_ok(r#"strstr("abc", "b");"#, "bc");
        check_ok(r#"strstr("abcbd", "b");"#, "bcbd");
        check_err(r#"strstr();"#, |err| {
            matches!(err, MissingPositionalArguments { .. })
        });
        check_err(r#"strstr("a");"#, |err| {
            matches!(err, MissingPositionalArguments { .. })
        });
    }
}
