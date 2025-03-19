use std::fmt::Debug;

use codespan_reporting::files::SimpleFile;

use crate::nasl::{
    Code, error,
    syntax::{Tokenizer, parser::grammar::Expr},
};

use super::{Parse, Parser, error::ParseError, grammar::Declaration};

// TODO incorporate into `Code` eventually.
fn parse<T: Parse>(file_name: &str, code: &str) -> Result<T, ParseError> {
    let code = Code::from_string_fake_filename(code, file_name)
        .code()
        .to_string();
    let tokenizer = Tokenizer::tokenize(&code);
    Parser::new(tokenizer).parse::<T>()
}

fn parse_program_ok(file_name: &str, code: &str) -> Vec<Declaration> {
    let code = Code::from_string_fake_filename(code, file_name)
        .code()
        .to_string();
    let tokens = Tokenizer::tokenize(&code);
    Parser::new(tokens).parse_program().unwrap().decls()
}

fn parse_program_err(file_name: &str, code: &str) -> String {
    let code = Code::from_string_fake_filename(code, file_name)
        .code()
        .to_string();
    let tokens = Tokenizer::tokenize(&code);
    error::emit_errors_str(
        &SimpleFile::new(file_name.to_string(), code.to_string()),
        Parser::new(tokens).parse_program().unwrap_err().into_iter(),
    )
}

pub fn parse_ok<T: Parse>(file_name: &str, code: &str) -> T {
    parse::<T>(file_name, code).unwrap()
}

pub fn parse_err<T: Parse + Debug>(file_name: &str, code: &str) -> String {
    error::emit_errors_str(
        &SimpleFile::new(file_name.to_string(), code.to_string()),
        vec![parse::<T>(file_name, code).unwrap_err()].into_iter(),
    )
}

// TODO: the program match is very ugly.
macro_rules! parse_test_ok {
    ($name: ident, Program, $($code: literal$(,)?)*) => {
        #[test]
        fn $name() {
            $(
                insta::assert_debug_snapshot!(crate::nasl::syntax::parser::tests::parse_program_ok(
                    stringify!($name),
                        $code
                ))
            )*
        }
    };
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
    ($name: ident, Program, $($code: literal$(,)?)*) => {
        #[test]
        fn $name() {
            $(
                insta::assert_snapshot!(crate::nasl::syntax::parser::tests::parse_program_err(
                    stringify!($name),
                        $code
                ));
            )*
        }
    };
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

parse_test_ok!(number_declaration, Declaration, "5;");
parse_test_err!(number_declaration_missing_semicolon, Declaration, "5");
parse_test_ok!(number_expr, Expr, "5");
parse_test_ok!(add_1, Expr, "5 + 3");
parse_test_ok!(add_mul, Expr, "5 + 3 * 4");
parse_test_ok!(var_assignment, Declaration, "x = 3;");
parse_test_ok!(
    multiple_declarations,
    Program,
    "a = 1;
     b = 2;
     c = 3;"
);
parse_test_err!(
    multiple_declarations_error,
    Program,
    "a = 1;
     a = b = 3;
     a = b = 3;"
);
parse_test_ok!(
    operator_assignment,
    Program,
    "
    a += 1;
    a -= 1;
    a /= 1;
    a *= 1;
    a %= 1;
    a >>= 1;
    a <<= 1;
    a >>>= 1;
    "
);

parse_test_ok!(
    unary_operators,
    Program,
    "
    -a;
    !a;
    - - -a;
    - - !a;
    ! ! !a;
    "
);

parse_test_ok!(
    unary_postfix_operators,
    Program,
    "
    a++;
    a--;
    a-- --;
    a++ ++;
    ++a++;
    "
);

parse_test_ok!(
    compare_operator,
    Program,
    "
    a !~ '1';
    a =~ '1';
    a >< '1';
    a >!< '1';
    a == '1';
    a != '1';
    a > '1';
    a < '1';
    a >= '1';
    a <= '1';
    "
);

parse_test_ok!(empty_program, Program, "");

parse_test_err!(wrong_tokens, Program, "\"foo");

parse_test_ok!(parentheses, Expr, "(3 + 4) * 5");
parse_test_ok!(multiple_parentheses, Expr, "(((a)))");

parse_test_ok!(
    array_expr,
    Program,
    "
    a[1];
    a[5 + 3];
    a[5 + (3 * 4)];
    a[1] * b[2];
    a[b[1]];
"
);
