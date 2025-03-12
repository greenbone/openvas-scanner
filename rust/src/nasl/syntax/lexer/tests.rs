use std::path::Path;

use crate::nasl::syntax::{parse, ParseInfo, Statement};

pub fn parse_ok(file_name: &str, code: &str) -> Vec<Statement> {
    let results = ParseInfo::new(code, Path::new(file_name));
    match results.result {
        Ok(results) => results,
        Err(_) => {
            results.emit_errors();
            panic!("Code failed to parse.")
        }
    }
}

pub fn parse_err(file_name: &str, code: &str) -> Vec<SyntaxError> {
    let results = ParseInfo::new(code, Path::new(file_name));
    match results.result {
        Ok(result) => {
            panic!(
                "Properly parsed code that should result in error. Parsing result: {:?}",
                result
            );
        }
        Err(errors) => errors,
    }
}

macro_rules! parse_test_ok {
    ($name: ident, $($code: literal$(,)?)*) => {
        #[test]
        fn $name() {
            $(
                insta::assert_snapshot!(crate::nasl::syntax::lexer::tests::parse_ok(
                    stringify!($name),
                        $code
                )
                .into_iter()
                .map(|stmt| stmt.to_string())
                .collect::<Vec<_>>()
                .join("\n"));
            )*
        }
    };
}

macro_rules! parse_test_err {
    ($name: ident, $($code: literal$(,)?)*) => {
        #[test]
        fn $name() {
            $(
                insta::assert_debug_snapshot!(crate::nasl::syntax::lexer::tests::parse_err(
                    stringify!($name),
                        $code
                ));
            )*
        }
    };
}

pub(crate) use {parse_test_err, parse_test_ok};

use core::panic;

use crate::nasl::syntax::token;

use super::*;

use StatementKind::*;
use TokenKind::*;

// simplified resolve method to verify a calculate with a given statement
fn resolve(s: &Statement) -> i64 {
    let callable = |stmts: &[Statement], calculus: Box<dyn Fn(i64, i64) -> i64>| -> i64 {
        let right = &stmts[1];
        let left = &stmts[0];
        calculus(resolve(left), resolve(right))
    };
    let single_callable = |stmts: &[Statement], calculus: Box<dyn Fn(i64) -> i64>| -> i64 {
        let left = &stmts[0];
        calculus(resolve(left))
    };
    match s.kind() {
        Primitive => match s.start().kind() {
            Literal(token::Literal::Number(num)) => *num,
            _ => todo!(),
        },
        Operator(head, rest) => match head {
            Tilde => single_callable(rest, Box::new(|left| !left)),
            Plus => callable(rest, Box::new(|left, right| left + right)),
            Minus if rest.len() == 1 => single_callable(rest, Box::new(|left| -left)),
            Minus => callable(rest, Box::new(|left, right| left - right)),
            Star => callable(rest, Box::new(|left, right| left * right)),
            Slash => callable(rest, Box::new(|left, right| left / right)),
            Percent => callable(rest, Box::new(|left, right| left % right)),
            LessLess => callable(rest, Box::new(|left, right| left << right)),
            GreaterGreater => callable(rest, Box::new(|left, right| left >> right)),
            Ampersand => callable(rest, Box::new(|left, right| left & right)),
            Pipe => callable(rest, Box::new(|left, right| left | right)),
            Caret => callable(rest, Box::new(|left, right| left ^ right)),
            GreaterGreaterGreater => {
                callable(
                    rest,
                    Box::new(|left, right| {
                        // this operator is used to drop signed bits
                        // so the result depends heavily if it is u32, u64, ...
                        // to have the same results as in javascript we use u32 in this example
                        let left_casted = left as u32;
                        (left_casted >> right) as i64
                    }),
                )
            }
            StarStar => callable(
                rest,
                Box::new(|left, right| (left as u32).pow(right as u32) as i64),
            ),
            token => {
                todo!("{:?}", token)
            }
        },
        _ => todo!("operator not found"),
    }
}

macro_rules! calculated_test {
    ($code:expr, $expected:expr) => {
        let expr = parse_ok("", $code).remove(0);
        assert_eq!(resolve(&expr), $expected);
    };
}

#[test]
fn ordering() {
    calculated_test!("1 + 5 * 6;", 31);
    calculated_test!("3 * 10 + 10 / 5;", 32);
    calculated_test!("3 * 10 / 5;", 6);
    calculated_test!("3 * 10 / 5 % 4;", 2);
    calculated_test!("1 - 1 - 1;", -1);
    calculated_test!("1 - 1 * 2;", -1);
}

#[test]
fn grouping() {
    calculated_test!("(2 + 5) * 2;", 14);
}

#[test]
fn pow() {
    calculated_test!("2 ** 4;", 16);
}

#[test]
fn bitwise_operations() {
    //shifting
    calculated_test!("1 << 2 * 3;", 64);
    calculated_test!("3 * 12 >> 2;", 9);
    calculated_test!("-5 >>> 2;", 1073741822);
    // operations
    calculated_test!("1 & 0;", 0);
    calculated_test!("~1 | 0;", -2);
    calculated_test!("1 ^ 1;", 0);
}

parse_test_ok!(
    operator_assignment,
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
    compare_operator,
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
    x() x 2;
    "
);

parse_test_ok!(logical_operator, "a && 1; a || 1;");

parse_test_ok!(assignment, "(a = 1);");

parse_test_ok!(variable_assignment_operator, "a++; a--; a[1]++; a[1]--;");

parse_test_ok!(primitive, "1;");
parse_test_ok!(variable, "a;");
parse_test_ok!(array, "a[1];");
parse_test_ok!(call, "a();");
parse_test_ok!(exit, "exit(0);");
parse_test_ok!(return_stmt, "return 0;");
parse_test_ok!(break_stmt, "break;");
parse_test_ok!(continue_stmt, "continue;");
parse_test_ok!(include, "include(\"test.inc\");");
parse_test_ok!(declare, "local_var a;");
parse_test_ok!(parameter, "[a, b];");
parse_test_ok!(named_parameter, "a: b;");
parse_test_ok!(assign, "a = 1;");
parse_test_ok!(add, "a + 1;");
parse_test_ok!(sub, "a - 1;");
parse_test_ok!(mul, "a * 1;");
parse_test_ok!(div, "a / 1;");
parse_test_ok!(modulo, "a % 1;");
parse_test_ok!(return_assign, "a++;");
parse_test_ok!(assign_return, "--a;");
parse_test_ok!(if_stmt, "if (a) b; else c;");
parse_test_ok!(for_stmt, "for (i = 0; i < 10; i++) a;");
parse_test_ok!(while_stmt, "while (a) b;");
parse_test_ok!(repeat, "repeat a; until b;");
parse_test_ok!(foreach, "foreach a(b) c;");
parse_test_ok!(block, "{ a; }");
parse_test_ok!(function_declaration, "function a(b) {c;}");
parse_test_ok!(no_op, ";");

parse_test_ok!(variables, "a;");
parse_test_ok!(arrays, "a[0];", "a = [1, 2, 3];", "a[0] = [1, 2, 4];");
parse_test_ok!(anon_function_call, "a(1, 2, 3);");
parse_test_ok!(
    named_function_call,
    "script_tag(name:\"cvss_base\", value:1 + 1 % 2);"
);

// test_err!(wrong_assignment, "a = ");
// test_err!(wrong_keyword_assignment, "a = for;");

#[test]
fn position() {
    let code = r#"
    a = 1 + 1;
    b = 2 * 2;
    a = ++a;
    arr = mkarray(a, b, c      );
    arr[++a];
    exit(1);
    return 1;
    include('test.inc');
    local_var a, b, c;
    global_var a, b, c;
    if (a) display(1); else display(2);
    for (i = 1; i < 10; i++) display(i);
    while(TRUE) display(i);
    foreach a(q) display(a);
    repeat display("q"); until 1;
    {
        a;
        b;
    }
    function register_packages( buf ) { return 1; }
    "#;
    let parser = parse(code);
    let expected = [
        "a = 1 + 1;",
        "b = 2 * 2;",
        "a = ++a;",
        "arr = mkarray(a, b, c      );",
        "arr[++a];",
        "exit(1);",
        "return 1;",
        "include('test.inc');",
        "local_var a, b, c;",
        "global_var a, b, c;",
        "if (a) display(1); else display(2);",
        "for (i = 1; i < 10; i++) display(i);",
        "while(TRUE) display(i);",
        "foreach a(q) display(a);",
        "repeat display(\"q\"); until 1;",
        r#"{
        a;
        b;
    }"#,
        "function register_packages( buf ) { return 1; }",
    ];
    let mut tests = 0;

    let mut ri = expected.iter();
    for stmt in parser.unwrap() {
        let a: &str = ri.next().unwrap();
        let range = stmt.range();
        tests += 1;
        assert_eq!(&code[range], a);
    }

    assert_eq!(tests, expected.len());
}
