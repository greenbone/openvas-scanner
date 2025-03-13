use codespan_reporting::files::SimpleFile;

use crate::nasl::{
    error,
    syntax::{parser::grammar::Expr, Tokenizer},
    Code,
};

use super::{error::ParseError, grammar::Declaration, Parse, Parser};

// TODO incorporate into `Code` eventually.
// TODO add tests for program parsing that take synchronization into account
fn parse<T: Parse>(file_name: &str, code: &str) -> Result<<T as Parse>::Output, ParseError> {
    let code = Code::from_string_fake_filename(code, file_name)
        .code()
        .to_string();
    let tokens = Tokenizer::tokenize(&code).unwrap();
    Parser::new(tokens).parse::<T>()
}

pub fn parse_ok<T: Parse>(file_name: &str, code: &str) -> <T as Parse>::Output {
    parse::<T>(file_name, code).unwrap()
}

pub fn parse_err<T: Parse>(file_name: &str, code: &str) -> String {
    error::emit_errors_str(
        &SimpleFile::new(file_name.to_string(), code.to_string()),
        vec![parse::<T>(file_name, code).unwrap_err()].into_iter(),
    )
}

macro_rules! parse_test_ok {
    ($name: ident, $ty: ty, $($code: literal$(,)?)*) => {
        #[test]
        fn $name() {
            $(
                insta::assert_debug_snapshot!(crate::nasl::syntax::parser::tests::parse_ok::<$ty>(
                    stringify!($name),
                        $code
                ))
            )*
        }
    };
}

macro_rules! parse_test_err {
    ($name: ident, $ty: ty, $($code: literal$(,)?)*) => {
        #[test]
        fn $name() {
            $(
                insta::assert_snapshot!(crate::nasl::syntax::parser::tests::parse_err::<$ty>(
                    stringify!($name),
                        $code
                ));
            )*
        }
    };
}

parse_test_ok!(number, Declaration, "5;");
parse_test_err!(missing_semicolon, Declaration, "5");
parse_test_err!(number_expr, Expr, "5");
