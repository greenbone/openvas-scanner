use std::fmt::Debug;

use codespan_reporting::files::SimpleFile;

use crate::nasl::{
    Code, error,
    syntax::{Tokenizer, parser::grammar::Expr},
};

use super::{Parse, Parser, error::SpannedError, grammar::Stmt};

// TODO incorporate into `Code` eventually.
fn parse<T: Parse>(file_name: &str, code: &str) -> Result<T, SpannedError> {
    let code = Code::from_string_fake_filename(code, file_name)
        .code()
        .to_string();
    let tokenizer = Tokenizer::tokenize(&code);
    Parser::new(tokenizer)
        .parse_span::<T>()
        .map_err(|e| e.unwrap_as_spanned())
}

fn parse_program_ok(file_name: &str, code: &str) -> Vec<Stmt> {
    let code = Code::from_string_fake_filename(code, file_name)
        .code()
        .to_string();
    let tokens = Tokenizer::tokenize(&code);
    Parser::new(tokens).parse_program().unwrap().stmts()
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
                ));
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
                ));
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

parse_test_ok!(number_declaration, Stmt, "5;");
parse_test_err!(number_declaration_missing_semicolon, Stmt, "5");
parse_test_ok!(number_expr, Expr, "5");
parse_test_ok!(add_1, Expr, "5 + 3");
parse_test_ok!(add_mul, Expr, "5 + 3 * 4");
parse_test_ok!(left_associativity, Expr, "3 - 3 - 3");
parse_test_ok!(var_assignment, Stmt, "x = 3;");
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

parse_test_ok!(logical_operator, Program, "a && 1; a || 1;");

parse_test_ok!(
    variable_assignment_operator,
    Program,
    "a++; a--; a[1]++; a[1]--;"
);

parse_test_ok!(primitive, Program, "1;");
parse_test_ok!(variable, Program, "a;");
parse_test_ok!(array, Program, "a[1];");
parse_test_ok!(assign, Program, "a = 1;");
parse_test_ok!(add, Program, "a + 1;");
parse_test_ok!(sub, Program, "a - 1;");
parse_test_ok!(mul, Program, "a * 1;");
parse_test_ok!(div, Program, "a / 1;");
parse_test_ok!(modulo, Program, "a % 1;");
parse_test_ok!(return_assign, Program, "a++;");
parse_test_ok!(assign_return, Program, "--a;");

parse_test_ok!(use_parser, Program, "a = 23;b = 1;");

parse_test_ok!(
    jsp_example,
    Program,
    r#"
    gms_path = gms_path + 'webapps\\appliance\\';
    jsp = '<% out.println( "' + jsp_print  + '" ); %>';
    "#
);

parse_test_ok!(
    unexpected_plusplus,
    Program,
    r###"
    cookie_jar[this_cookie]++;
    "###
);

parse_test_ok!(anon_function_call, Program, "a(1, 2, 3);");
parse_test_err!(function_call_unclosed, Program, "a(1, 2, 3");
parse_test_ok!(
    named_function_call,
    Program,
    "script_tag(name:\"cvss_base\", value:1 + 1 % 2);"
);
parse_test_ok!(
    mixed_function_call,
    Program,
    "script_tag(\"foo\", name:\"cvss_base\", value:1 + 1 % 2);"
);
parse_test_ok!(nested_function_call, Program, "foo(bar(3), 4);",);
parse_test_err!(missing_commas_function_call, Program, "foo(1 2 3);");
parse_test_ok!(empty_function_call, Program, "a();");

parse_test_ok!(array_literal, Program, "a = [1, 2, 3];",);
parse_test_err!(array_literal_unclosed, Program, "a = [1, 2, 3;",);

parse_test_ok!(no_op, Program, ";");

parse_test_ok!(block, Program, "{ a; }");
parse_test_ok!(block_empty, Program, "{ }");
parse_test_ok!(block_multiple_stmts, Program, "{ a; b; c; }");
parse_test_ok!(nested_blocks, Program, "{ a; { b; c; } }");
parse_test_err!(error_in_block, Program, "{ a =3; b=; }");

parse_test_ok!(include, Program, "include(\"test.inc\");");

parse_test_ok!(function_declaration, Program, "function a(b) {c;}");
parse_test_ok!(
    function_declaration_with_decls,
    Program,
    "function a(b) {c = 3;}"
);

parse_test_ok!(return_stmt, Program, "function a(b) { return 0; }");

parse_test_ok!(while_loop_single_stmt, Program, "while (a) b = 3;");
parse_test_ok!(while_loop_block, Program, "while (a) { b; d = 3; }");

parse_test_ok!(break_while, Program, "while (a) { b = 2; break; }");
parse_test_ok!(continue_while, Program, "while (a) { b = 2; continue; }");

parse_test_ok!(declare_local_var, Program, "local_var a;");
parse_test_ok!(declare_global_var, Program, "global_var a;");

// parse_test_ok!(array_assignment, Program, "a[1] = 3;");
// parse_test_ok!(parameter, Program, "[a, b];");
// parse_test_ok!(named_parameter, Program, "a: b;");
// parse_test_ok!(repeat, Program, "repeat a; until b;");
// parse_test_ok!(foreach, Program, "foreach a(b) c;");
// parse_test_ok!(
//     change_to_peek,
//     Program,
//     "send_packet( udp, pcap_active:FALSE ) x 200;"
// );
// parse_test_ok!(exit, Program, "exit(0);");
// parse_test_ok!(if_stmt, Program, "if (a) b; else c;");
// parse_test_ok!(for_stmt, Program, "for (i = 0; i < 10; i++) a;");
// parse_test_ok!(
//     position,
//     Program,
//     r#"
//         a = 1 + 1;
//         b = 2 * 2;
//         a = ++a;
//         arr = mkarray(a, b, c      );
//         arr[++a];
//         exit(1);
//         return 1;
//         include('test.inc');
//         local_var a, b, c;
//         global_var a, b, c;
//         if (a) display(1); else display(2);
//         for (i = 1; i < 10; i++) display(i);
//         while(TRUE) display(i);
//         foreach a(q) display(a);
//         repeat display("q"); until 1;
//         {
//             a;
//             b;
//         }
//         function register_packages( buf ) { return 1; }
//     "#
// );
//
// parse_test_ok!(
//     unexpected_assign,
//     Program,
//     r###"
//     while(y = recv(socket:soc, length:1024)) {
//     buf1 += y;
//     }
//     "###
// );
//
// parse_test_ok!(
//     unexpected_noop,
//     Program,
//     r###"
//     if( ! version || version == '' ) return;
//     "###
// );
//
// parse_test_ok!(
//     unexpected_equal_operator,
//     Program,
//     r###"
// # Message Server runs on ports 36xx or 39xx
// if (port < 3600 || port >= 3700)
// if (port < 3900 || port >= 4000)
// exit(0);
//
// soc = open_sock_tcp(port);
//
//     "###
// );
//
// parse_test_ok!(
//     stack_overflow,
//     Program,
//     r###"
//         req = raw_string(0x00, 0x00, 0x03, 0x14, 0x08, 0x14, 0xff, 0x9f,
//                 0xde, 0x5d, 0x5f, 0xb3, 0x07, 0x8f, 0x49, 0xa7,
//                 0x79, 0x6a, 0x03, 0x3d, 0xaf, 0x55, 0x00, 0x00,
//                 0x00, 0x7e, 0x64, 0x69, 0x66, 0x66, 0x69, 0x65,
//                 0x2d, 0x68, 0x65, 0x6c, 0x6c, 0x6d, 0x61, 0x6e,
//                 0x2d, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x2d, 0x65,
//                 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x2d,
//                 0x73, 0x68, 0x61, 0x32, 0x35, 0x36, 0x2c, 0x64,
//                 0x69, 0x66, 0x66, 0x69, 0x65, 0x2d, 0x68, 0x65,
//                 0x6c, 0x6c, 0x6d, 0x61, 0x6e, 0x2d, 0x67, 0x72,
//                 0x6f, 0x75, 0x70, 0x2d, 0x65, 0x78, 0x63, 0x68,
//                 0x61, 0x6e, 0x67, 0x65, 0x2d, 0x73, 0x68, 0x61,
//                 0x31, 0x2c, 0x64, 0x69, 0x66, 0x66, 0x69, 0x65,
//                 0x2d, 0x68, 0x65, 0x6c, 0x6c, 0x6d, 0x61, 0x6e,
//                 0x2d, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x31, 0x34,
//                 0x2d, 0x73, 0x68, 0x61, 0x31, 0x2c, 0x64, 0x69,
//                 0x66, 0x66, 0x69, 0x65, 0x2d, 0x68, 0x65, 0x6c,
//                 0x6c, 0x6d, 0x61, 0x6e, 0x2d, 0x67, 0x72, 0x6f,
//                 0x75, 0x70, 0x31, 0x2d, 0x73, 0x68, 0x61, 0x31,
//                 0x00, 0x00, 0x00, 0x0f, 0x73, 0x73, 0x68, 0x2d,
//                 0x72, 0x73, 0x61, 0x2c, 0x73, 0x73, 0x68, 0x2d,
//                 0x64, 0x73, 0x73, 0x00, 0x00, 0x00, 0x9d, 0x61,
//                 0x65, 0x73, 0x31, 0x32, 0x38, 0x2d, 0x63, 0x62,
//                 0x63, 0x2c, 0x33, 0x64, 0x65, 0x73, 0x2d, 0x63,
//                 0x62, 0x63, 0x2c, 0x62, 0x6c, 0x6f, 0x77, 0x66,
//                 0x69, 0x73, 0x68, 0x2d, 0x63, 0x62, 0x63, 0x2c,
//                 0x63, 0x61, 0x73, 0x74, 0x31, 0x32, 0x38, 0x2d,
//                 0x63, 0x62, 0x63, 0x2c, 0x61, 0x72, 0x63, 0x66,
//                 0x6f, 0x75, 0x72, 0x31, 0x32, 0x38, 0x2c, 0x61,
//                 0x72, 0x63, 0x66, 0x6f, 0x75, 0x72, 0x32, 0x35,
//                 0x36, 0x2c, 0x61, 0x72, 0x63, 0x66, 0x6f, 0x75,
//                 0x72, 0x2c, 0x61, 0x65, 0x73, 0x31, 0x39, 0x32,
//                 0x2d, 0x63, 0x62, 0x63, 0x2c, 0x61, 0x65, 0x73,
//                 0x32, 0x35, 0x36, 0x2d, 0x63, 0x62, 0x63, 0x2c,
//                 0x72, 0x69, 0x6a, 0x6e, 0x64, 0x61, 0x65, 0x6c,
//                 0x2d, 0x63, 0x62, 0x63, 0x40, 0x6c, 0x79, 0x73,
//                 0x61, 0x74, 0x6f, 0x72, 0x2e, 0x6c, 0x69, 0x75,
//                 0x2e, 0x73, 0x65, 0x2c, 0x61, 0x65, 0x73, 0x31,
//                 0x32, 0x38, 0x2d, 0x63, 0x74, 0x72, 0x2c, 0x61,
//                 0x65, 0x73, 0x31, 0x39, 0x32, 0x2d, 0x63, 0x74,
//                 0x72, 0x2c, 0x61, 0x65, 0x73, 0x32, 0x35, 0x36,
//                 0x2d, 0x63, 0x74, 0x72, 0x00, 0x00, 0x00, 0x9d,
//                 0x61, 0x65, 0x73, 0x31, 0x32, 0x38, 0x2d, 0x63,
//                 0x62, 0x63, 0x2c, 0x33, 0x64, 0x65, 0x73, 0x2d,
//                 0x63, 0x62, 0x63, 0x2c, 0x62, 0x6c, 0x6f, 0x77,
//                 0x66, 0x69, 0x73, 0x68, 0x2d, 0x63, 0x62, 0x63,
//                 0x2c, 0x63, 0x61, 0x73, 0x74, 0x31, 0x32, 0x38,
//                 0x2d, 0x63, 0x62, 0x63, 0x2c, 0x61, 0x72, 0x63,
//                 0x66, 0x6f, 0x75, 0x72, 0x31, 0x32, 0x38, 0x2c,
//                 0x61, 0x72, 0x63, 0x66, 0x6f, 0x75, 0x72, 0x32,
//                 0x35, 0x36, 0x2c, 0x61, 0x72, 0x63, 0x66, 0x6f,
//                 0x75, 0x72, 0x2c, 0x61, 0x65, 0x73, 0x31, 0x39,
//                 0x32, 0x2d, 0x63, 0x62, 0x63, 0x2c, 0x61, 0x65,
//                 0x73, 0x32, 0x35, 0x36, 0x2d, 0x63, 0x62, 0x63,
//                 0x2c, 0x72, 0x69, 0x6a, 0x6e, 0x64, 0x61, 0x65,
//                 0x6c, 0x2d, 0x63, 0x62, 0x63, 0x40, 0x6c, 0x79,
//                 0x73, 0x61, 0x74, 0x6f, 0x72, 0x2e, 0x6c, 0x69,
//                 0x75, 0x2e, 0x73, 0x65, 0x2c, 0x61, 0x65, 0x73,
//                 0x31, 0x32, 0x38, 0x2d, 0x63, 0x74, 0x72, 0x2c,
//                 0x61, 0x65, 0x73, 0x31, 0x39, 0x32, 0x2d, 0x63,
//                 0x74, 0x72, 0x2c, 0x61, 0x65, 0x73, 0x32, 0x35,
//                 0x36, 0x2d, 0x63, 0x74, 0x72, 0x00, 0x00, 0x00,
//                 0x69, 0x68, 0x6d, 0x61, 0x63, 0x2d, 0x6d, 0x64,
//                 0x35, 0x2c, 0x68, 0x6d, 0x61, 0x63, 0x2d, 0x73,
//                 0x68, 0x61, 0x31, 0x2c, 0x75, 0x6d, 0x61, 0x63,
//                 0x2d, 0x36, 0x34, 0x40, 0x6f, 0x70, 0x65, 0x6e,
//                 0x73, 0x73, 0x68, 0x2e, 0x63, 0x6f, 0x6d, 0x2c,
//                 0x68, 0x6d, 0x61, 0x63, 0x2d, 0x72, 0x69, 0x70,
//                 0x65, 0x6d, 0x64, 0x31, 0x36, 0x30, 0x2c, 0x68,
//                 0x6d, 0x61, 0x63, 0x2d, 0x72, 0x69, 0x70, 0x65,
//                 0x6d, 0x64, 0x31, 0x36, 0x30, 0x40, 0x6f, 0x70,
//                 0x65, 0x6e, 0x73, 0x73, 0x68, 0x2e, 0x63, 0x6f,
//                 0x6d, 0x2c, 0x68, 0x6d, 0x61, 0x63, 0x2d, 0x73,
//                 0x68, 0x61, 0x31, 0x2d, 0x39, 0x36, 0x2c, 0x68,
//                 0x6d, 0x61, 0x63, 0x2d, 0x6d, 0x64, 0x35, 0x2d,
//                 0x39, 0x36, 0x00, 0x00, 0x00, 0x69, 0x68, 0x6d,
//                 0x61, 0x63, 0x2d, 0x6d, 0x64, 0x35, 0x2c, 0x68,
//                 0x6d, 0x61, 0x63, 0x2d, 0x73, 0x68, 0x61, 0x31,
//                 0x2c, 0x75, 0x6d, 0x61, 0x63, 0x2d, 0x36, 0x34,
//                 0x40, 0x6f, 0x70, 0x65, 0x6e, 0x73, 0x73, 0x68,
//                 0x2e, 0x63, 0x6f, 0x6d, 0x2c, 0x68, 0x6d, 0x61,
//                 0x63, 0x2d, 0x72, 0x69, 0x70, 0x65, 0x6d, 0x64,
//                 0x31, 0x36, 0x30, 0x2c, 0x68, 0x6d, 0x61, 0x63,
//                 0x2d, 0x72, 0x69, 0x70, 0x65, 0x6d, 0x64, 0x31,
//                 0x36, 0x30, 0x40, 0x6f, 0x70, 0x65, 0x6e, 0x73,
//                 0x73, 0x68, 0x2e, 0x63, 0x6f, 0x6d, 0x2c, 0x68,
//                 0x6d, 0x61, 0x63, 0x2d, 0x73, 0x68, 0x61, 0x31,
//                 0x2d, 0x39, 0x36, 0x2c, 0x68, 0x6d, 0x61, 0x63,
//                 0x2d, 0x6d, 0x64, 0x35, 0x2d, 0x39, 0x36, 0x00,
//
//                 ##3rd byte in this next line causes crash
//                 0x00, 0x00, 0x28, 0x7a, 0x6c, 0x69, 0x62, 0x40,
//                 0x6f, 0x70, 0x65, 0x6e, 0x73, 0x73, 0x68, 0x2e,
//                 0x63, 0x6f, 0x6d, 0x2c, 0x7a, 0x6c, 0x69, 0x62,
//                 0x2c, 0x6e, 0x6f, 0x6e, 0x65, 0x00, 0x00, 0x00,
//                 0x1a, 0x7a, 0x6c, 0x69, 0x62, 0x40, 0x6f, 0x70,
//                 0x65, 0x6e, 0x73, 0x73, 0x68, 0x2e, 0x63, 0x6f,
//                 0x6d, 0x2c, 0x7a, 0x6c, 0x69, 0x62, 0x2c, 0x6e,
//                 0x6f, 0x6e, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00,
//                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//                 0x0a);
//     "###
// );

// parse_test_ok!(assignment, Program, "(a = 1);");
// TODO?
// test_err!(wrong_assignment, "a = ");
// test_err!(wrong_keyword_assignment, "a = for;");

// TODO!
// parse_test_err!(break_stmt_outside_loop, Program, "break;");
// parse_test_err!(continue_stmt_outside_loop, Program, "continue;");
// parse_test_err!(return_stmt_outside_fn, Program, "return 0;");
