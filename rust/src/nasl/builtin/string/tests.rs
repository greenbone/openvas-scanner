// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception
#[cfg(test)]
mod tests {
    use crate::nasl::{test_prelude::*, utils::error::ArgumentError};
    use ArgumentError::*;
    use NaslValue::*;

    #[test]
    fn hexstr() {
        check_code_result("hexstr('foo');", "666f6f");
        check_err_matches!(
            "hexstr('foo', 'I will be ignored');",
            TrailingPositionals { .. },
        );
        check_code_result("hexstr(6);", Null);
        check_code_result("hexstr();", Null);
        check_code_result("hexstr(raw_string(10, 208, 102, 165, 210, 159, 63, 42, 42, 28, 124, 23, 221, 8, 42, 121));", "0ad066a5d29f3f2a2a1c7c17dd082a79");
    }

    #[test]
    fn raw_string() {
        check_code_result("raw_string(0x7B);", vec![123u8]);
        check_code_result("raw_string(0x7B, 1);", vec![123u8, 1]);
        check_code_result(
            "raw_string(0x7B, 1, 'Hallo');",
            vec![123u8, 1, 72, 97, 108, 108, 111],
        );
    }

    #[test]
    fn tolower() {
        check_code_result("tolower(0x7B);", Null);
        check_code_result("tolower('HALLO');", "hallo");
    }

    #[test]
    fn toupper() {
        check_code_result("toupper(0x7B);", Null);
        check_code_result("toupper('hallo');", "HALLO");
        check_code_result("toupper();", Null);
    }

    #[test]
    fn strlen() {
        check_code_result("strlen(0x7B);", 0i64);
        check_code_result("strlen('hallo');", 5i64);
        check_code_result("strlen('hallo\n');", 6i64);
        check_code_result(r#"strlen("hallo\n");"#, 7i64);
    }

    #[test]
    fn string() {
        check_code_result("string(0x7B);", "123");
        check_code_result("string(0x7B, 1);", "1231");
        check_code_result("string(0x7B, 1, 'Hallo');", "1231Hallo");
        check_code_result("string(0x7B, 1, NULL, 'Hallo');", "1231Hallo");
    }

    #[test]
    fn substr() {
        check_code_result("substr('hello', 1);", "ello");
        check_code_result("substr('hello', 0, 4);", "hell");
        check_code_result("substr('hello', 6);", Null);
    }

    #[test]
    fn crap() {
        check_code_result("crap(5);", "XXXXX");
        check_code_result("crap(5);", "XXXXX");
        check_code_result("crap(length: 5);", "XXXXX");
        check_code_result(r#"crap(data: "ab", length: 5);"#, "ababababab");
        check_code_result(r#"crap(data: 'ab', length: 5);"#, "ababababab");
        check_code_result(r#"crap(data: 'a\n', length: 2);"#, "a\na\n");
        check_code_result(r#"crap(data: "a\n", length: 2);"#, "a\\na\\n");
    }

    #[test]
    fn chomp() {
        check_code_result("chomp('abc');", "abc");
        check_code_result("chomp('abc\n');", "abc");
        check_code_result("chomp('abc  ');", "abc");
        check_code_result("chomp('abc\n\t\r ');", "abc");
        check_err_matches!("chomp();", MissingPositionals { .. });
    }

    #[test]
    fn stridx() {
        check_code_result(r#"stridx("abc", "bcd");"#, -1);
        check_code_result(r#"stridx("abc", "bc");"#, 1);
        check_code_result(r#"stridx("abc", "abc");"#, 0);
        check_code_result(r#"stridx("blahabc", "abc", 4);"#, 0);
        check_code_result(r#"stridx("blahabc", "abc", 3);"#, 1);
        check_code_result(r#"stridx("blahbc", "abc", 2);"#, -1);
    }

    #[test]
    fn display() {
        check_code_result("display('abc');", Null);
        check_code_result(r#"display("abc");"#, Null);
    }

    #[test]
    fn hexstr_to_data() {
        let mut t = TestBuilder::default();
        t.ok(
            r#"a = hexstr_to_data("4bb3c4a4f893ad8c9bdc833c325d62b3");"#,
            vec![
                75u8, 179, 196, 164, 248, 147, 173, 140, 155, 220, 131, 60, 50, 93, 98, 179,
            ],
        );
        t.ok(r#"data_to_hexstr(a);"#, "4bb3c4a4f893ad8c9bdc833c325d62b3");
    }

    #[test]
    fn ord() {
        check_code_result(r#"ord("a");"#, 97);
        check_code_result(r#"ord("b");"#, 98);
        check_code_result(r#"ord("c");"#, 99);
        check_code_result(r#"ord("\n");"#, 92);
        check_code_result(r#"ord('\n');"#, 10);
        check_code_result(r#"ord("c");"#, 99);
        check_code_result(r#"ord("");"#, Null);
        check_code_result("ord(1);", 49);
        check_err_matches!("ord();", MissingPositionals { .. });
    }

    #[test]
    fn match_() {
        check_code_result(r#"match(string: "abcd", pattern: "*cd");"#, true);
        check_code_result(r#"match(string: "abcd", pattern: "*CD");"#, false);
        check_code_result(
            r#"match(string: "abcd", pattern: "*CD", icase: FALSE);"#,
            false,
        );
        check_code_result(
            r#"match(string: "abcd", pattern: "*CD", icase: TRUE);"#,
            true,
        );
        // g_pattern_spec allows globs to match slashes, make sure we do too
        check_code_result(r#"match(string: "a///", pattern: "a*");"#, true);
        check_code_result(r#"match(string: "///a", pattern: "*a");"#, true);
        check_err_matches!(r#"match(string: "abcd");"#, MissingNamed { .. });
        check_err_matches!(r#"match(pattern: "ab");"#, MissingNamed { .. });
    }

    #[test]
    fn hex() {
        check_code_result(r#"hex(0);"#, "0x00");
        check_code_result(r#"hex(32);"#, "0x20");
        check_code_result(r#"hex(255);"#, "0xff");
        check_code_result(r#"hex(256);"#, "0x00");
        check_code_result(r#"hex(257);"#, "0x01");
        check_code_result(r#"hex(-2);"#, "0xfe");
        check_err_matches!(r#"hex();"#, MissingPositionals { .. });
    }

    #[test]
    fn insstr() {
        check_code_result(r#"insstr("foo bar", "rab", 4);"#, "foo rab");
        check_code_result(r#"insstr("foo bar", "rab", 4, 100);"#, "foo rab");
        check_code_result(r#"insstr("foo bar", "rab", 4, 5);"#, "foo rabr");
        check_err_matches!(r#"insstr("foo bar", "rab", 4, 0);"#, WrongArgument { .. });
    }

    #[test]
    fn insstr_data_new_line() {
        check_code_result(r#"insstr('foo\nbar', "123456", 4 ,5);"#, "foo\n123456r");
    }

    #[test]
    fn insstr_string_new_line() {
        check_code_result(r#"insstr("foo\nbar", "123456", 4 ,5);"#, "foo\\123456ar");
    }

    #[test]
    fn int() {
        check_code_result(r#"int("123");"#, 123);
        check_code_result(r#"int(123);"#, 123);
        check_code_result(r#"int("123x");"#, 123);
        check_code_result(r#"int("123xx");"#, 0);
        check_code_result(r#"int(TRUE);"#, 1);
    }

    #[test]
    fn split_string_default_new_line() {
        check_code_result(r#"split("a\nb\nc");"#, vec!["a\\nb\\nc".to_string()]);
    }

    #[test]
    fn split_data_default_new_line() {
        check_code_result(
            "split('a\nb\nc');",
            vec!["a\n".to_string(), "b\n".to_string(), "c".to_string()],
        );
    }

    #[test]
    fn split_data_default_new_line_no_keep() {
        check_code_result(
            "split('a\nb\nc', keep: FALSE);",
            vec!["a".to_string(), "b".to_string(), "c".to_string()],
        );
    }

    #[test]
    fn split() {
        check_code_result(
            r#"split("a;b;c", sep: ";");"#,
            vec!["a;".to_string(), "b;".to_string(), "c".to_string()],
        );
        check_err_matches!(r#"split();"#, MissingPositionals { .. });
    }

    #[test]
    fn replace() {
        check_code_result(
            r#"str_replace(string: "abc", find: "b", replace: "foo");"#,
            "afooc",
        );
        check_err_matches!(r#"str_replace();"#, MissingNamed { .. });
        check_err_matches!(r#"str_replace(string: "abc");"#, MissingNamed { .. });
        check_code_result(r#"str_replace(string: "abc", find: "b");"#, "ac");
        check_code_result(
            r#"str_replace(string: "abcbd", find: "b", count: 1);"#,
            "acbd",
        );
        check_code_result(r#"str_replace(string: "ab\nc", find: "\n");"#, "abc");
        check_code_result(r#"str_replace(string: 'ab\nc', find: '\n');"#, "abc");
        check_code_result(r#"str_replace(string: 'ab\nc', find: "\n");"#, "ab\nc");
    }

    #[test]
    fn strstr() {
        check_code_result(r#"strstr("abc", "b");"#, "bc");
        check_code_result(r#"strstr("abcbd", "b");"#, "bcbd");
        check_code_result(r#"strstr('a\rbcbd', '\rb');"#, "\rbcbd");
        check_err_matches!(r#"strstr();"#, MissingPositionals { .. });
        check_err_matches!(r#"strstr("a");"#, MissingPositionals { .. });
    }
}
