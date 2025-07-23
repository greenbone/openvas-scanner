use crate::nasl::Code;

use super::*;

pub fn tokenize_ok(file_name: &str, code: &str) -> Vec<Token> {
    let results = Code::from_string_filename(code, file_name).tokenize();
    results.emit_errors().unwrap()
}

fn tokenize_err(file_name: &str, code: &str) -> String {
    let results = Code::from_string_filename(code, file_name).tokenize();
    results.unwrap_errors_str()
}

macro_rules! test_ok {
    ($name: ident, $code: literal) => {
        #[test]
        fn $name() {
            insta::assert_debug_snapshot!(tokenize_ok(stringify!($name), $code));
        }
    };
}

macro_rules! test_err {
    ($name: ident, $code: literal) => {
        #[test]
        fn $name() {
            insta::assert_snapshot!(tokenize_err(stringify!($name), $code));
        }
    };
}

test_ok!(skip_whitespace, "     (       ");

test_ok!(one_char_tokens, "( ) [ ] { } . - + % ; / * : ~ & | ^");
test_ok!(
    two_char_tokens,
    "& && | || ! != !~ = == =~ > >> >= >< < << <= - -- + += ++ / /= * ** *="
);
test_ok!(three_char_tokens, ">>> >>= >!< <<=");

test_ok!(four_symbol_tokens, ">>>=");

test_ok!(string, "\"I am a closed string \"");
test_err!(unclosed_string, "\"hello I am a unclosed string\\");

test_ok!(data_string, r#"'Hello \\\'you\\\'!'"#);
test_err!(unclosed_data_string, "'Hello \\'you\\'!\\'");

test_ok!(simple_number, "1");
test_ok!(
    numbers,
    "0 0b01 1234567890 012345670 0x1234567890ABCDEF 0b02"
);
test_err!(invalid_numbers, "0x 0b 0b2");
test_err!(invalid_hex_characters, "0x123h");

test_ok!(single_line_comments, "# this is a comment\n;");

test_ok!(identifier, "help_lo _hello _h4llo 4_h4llo");

test_ok!(
    keywords,
    "for foreach if else while repeat until local_var global_var return include exit break continue"
);
test_ok!(keyword_literals, "TRUE FALSE NULL");

test_ok!(string_quoting, r"'webapps\\\\appliance\\\\'");

test_ok!(data_escape_quoting, r#"'version=\"1.0\"'"#);

test_ok!(simplified_ipv4_address, "10.187.76.12");
test_err!(wrong_ipv4_address, "10.0x 10.0.x 10.0.0.x");

test_ok!(repeat_x_times, "x() x 10;");

test_ok!(use_tokenizer, "local_var hello = 'World!';");
