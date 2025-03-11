use std::path::Path;

use codespan_reporting::files::SimpleFiles;

use crate::nasl::{error::emit_errors, syntax::utils::read_single_files};

use super::*;

fn tokenize(
    file_name: &str,
    code: &str,
) -> (
    SimpleFiles<String, String>,
    usize,
    Result<Vec<Token>, Vec<TokenizerError>>,
) {
    let (files, file_id) = read_single_files(Path::new(file_name), code);
    let tokens = Tokenizer::tokenize(code);
    (files, file_id, tokens)
}

fn tokenize_ok(file_name: &str, code: &str) -> Vec<Token> {
    let (files, file_id, results) = tokenize(file_name, code);
    match results {
        Ok(results) => results,
        Err(errors) => {
            emit_errors(&files, file_id, errors.into_iter());
            panic!()
        }
    }
}

fn tokenize_err(file_name: &str, code: &str) -> Vec<TokenizerError> {
    let (_, _, results) = tokenize(file_name, code);
    match results {
        Ok(_) => {
            panic!("Properly tokenized code that should result in error.")
        }
        Err(errors) => errors,
    }
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
            insta::assert_debug_snapshot!(tokenize_err(stringify!($name), $code));
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
test_ok!(unclosed_string, "\"hello I am a unclosed string\\");

test_ok!(data_string, r#"'Hello \\\'you\\\'!'"#);
test_ok!(unclosed_data_string, "'Hello \\'you\\'!\\'");

test_ok!(simple_number, "1");
test_ok!(
    numbers,
    "0 0b01 1234567890 012345670 0x1234567890ABCDEF 0b02"
);
test_err!(invalid_numbers, "0x 0b 0b2");
test_err!(invalid_hex_characters, "0x123h");

test_ok!(single_line_comments, "# this is a comment\n;");

test_ok!(identifier, "help_lo _hello _h4llo 4_h4llo");

test_ok!(keywords, "for foreach if else while repeat until local_var global_var NULL return include exit break continue");

test_ok!(string_quoting, r"'webapps\\\\appliance\\\\'");

test_ok!(data_escape_quoting, r#"'version=\"1.0\"'"#);

test_ok!(simplified_ipv4_address, "10.187.76.12");

test_ok!(repeat_x_times, "x() x 10;");
