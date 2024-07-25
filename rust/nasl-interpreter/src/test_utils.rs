//! Utilities to test the outcome of NASL functions

use crate::*;
use nasl_builtin_utils::{function::ToNaslResult, NaslResult};

/// Check that a single line of code fulfills some property by running
/// a check function on the result.
pub fn check_line_of_code(code: &str, f: impl Fn(NaslResult)) {
    let mut vals = run(code);
    f(vals.remove(0))
}

/// Check that the returned error from a line of NASL code fulfills a given
/// property
pub fn check_err(code: &str, f: impl Fn(&FunctionErrorKind) -> bool) {
    check_line_of_code(code, |val| {
        let err = val.unwrap_err();
        assert!(f(&err), "Found {}", &err);
    });
}

/// Check that the value returned from a line of NASL code is
/// Ok(...) and that the inner value is equal to the expected
/// value.
pub fn check_ok(code: &str, expected: impl ToNaslResult) {
    let expected = expected.to_nasl_result().unwrap();
    check_line_of_code(code, |val| {
        let val = val.unwrap();
        assert_eq!(val, expected);
    });
}

/// Check that the expected value of multiple lines of NASL code
/// matches the given values.
pub fn check_multiple(code: &str, expected: Vec<impl ToNaslResult>) {
    let vals = run(code);
    for (val, expected) in vals.into_iter().zip(expected.into_iter()) {
        assert_eq!(val, Ok(expected.to_nasl_result().unwrap()));
    }
}

/// Check that the expected value of multiple lines of NASL code
/// matches the given values.
pub fn run(code: &str) -> Vec<NaslResult> {
    let register = Register::default();
    let binding = ContextFactory::default();
    let context = binding.build(Default::default(), Default::default());
    let parser = CodeInterpreter::new(code, register, &context);
    parser
        .map(|res| {
            res.map_err(|e| match e.kind {
                InterpretErrorKind::FunctionCallError(f) => f.kind,
                _ => panic!(),
            })
        })
        .collect()
}

/// Check that the line of NASL code returns an Err variant
/// and that the inner error matches a pattern.
#[macro_export]
macro_rules! check_err_matches {
    ($code: literal, $pat: pat) => {
        ::nasl_interpreter::test_utils::check_err($code, |e| matches!(e, $pat));
    };
}

/// Check that the line of NASL code returns an Ok variant
/// and that the inner value matches a pattern.
#[macro_export]
macro_rules! check_ok_matches {
    ($code: literal, $pat: pat) => {
        ::nasl_interpreter::test_utils::check_line_of_code($code, |res| {
            assert!(matches!(res, Ok($pat)));
        });
    };
}
