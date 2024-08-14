//! Utilities to test the outcome of NASL functions

use crate::*;
use futures::StreamExt;
use nasl_builtin_utils::{function::ToNaslResult, NaslResult};
use storage::Storage;

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
    vec![1, 2, 3];
}

/// Check that the expected value of multiple lines of NASL code
/// matches the given values.
pub fn check_multiple(code: &str, expected: Vec<impl ToNaslResult>) {
    let vals = run(code);
    for (val, expected) in vals.into_iter().zip(expected.into_iter()) {
        assert_eq!(val, Ok(expected.to_nasl_result().unwrap()));
    }
}

/// Todo DOC
pub fn run_custom_context<L, S>(code: &str, binding: ContextFactory<L, S>) -> Vec<NaslResult>
where
    L: Loader,
    S: Storage,
{
    let register = Register::default();
    let context = binding.build(Default::default());
    let parser = CodeInterpreter::new(code, register, &context);
    futures::executor::block_on(async {
        parser
            .stream()
            .map(|res| {
                res.map_err(|e| match e.kind {
                    InterpretErrorKind::FunctionCallError(f) => f.kind,
                    e => panic!("Unkown error: {}", e),
                })
            })
            .collect()
            .await
    })
}

/// Check that the expected value of multiple lines of NASL code
/// matches the given values.
pub fn run(code: &str) -> Vec<NaslResult> {
    run_custom_context(code, ContextFactory::default())
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

#[macro_export]
/// TODO: Doc
macro_rules! _internal_nasl_test_code {
    ($arr_name: ident, $code: literal == $expr:expr, $($tt: tt)*) => {
        $arr_name.push($code);
        $crate::_internal_nasl_test_code!($arr_name, $($tt)*);
    };
    ($arr_name: ident, $code: literal throws $expr:expr, $($tt: tt)*) => {
        $arr_name.push($code);
        $crate::_internal_nasl_test_code!($arr_name, $($tt)*);
    };
    ($arr_name: ident, $code: literal, $($tt: tt)*) => {
        $arr_name.push($code);
        $crate::_internal_nasl_test_code!($arr_name, $($tt)*);
    };
    ($arr_name: ident,) => {};
}

#[macro_export]
/// TODO: Doc
macro_rules! _internal_nasl_test_expr {
    ($arr_name: ident, $count: ident, $code: literal == $expr:expr, $($tt: tt)*) => {
        #[allow(unused)]
        use ::nasl_builtin_utils::function::ToNaslResult as _;
        let converted = $expr.to_nasl_result().unwrap();
        assert_eq!(
            $arr_name.get($count).unwrap(),
            &Ok(converted),
            "Mismatch in line {} with code \"{}\". Expected 'Ok({})', found '{:?}'",
            $count,
            $code,
            stringify!($expr),
            $arr_name.get($count).unwrap()
        );
        $count += 1;
        $crate::_internal_nasl_test_expr!($arr_name, $count, $($tt)*);
    };
    ($arr_name: ident, $count: ident, $code: literal throws $pat:pat, $($tt: tt)*) => {
        assert!(matches!($arr_name.get($count).unwrap(), Err($pat)),
            "Mismatch in line {} with code \"{}\". Expected 'Err({})', found '{:?}'",
            $count,
            $code,
            stringify!($pat),
            $arr_name.get($count).unwrap()
        );
        $count += 1;
        $crate::_internal_nasl_test_expr!($arr_name, $count, $($tt)*);
    };
    ($arr_name: ident, $count: ident, $code: literal, $($tt: tt)*) => {
        $count += 1;
        $crate::_internal_nasl_test_expr!($arr_name, $count, $($tt)*);
    };
    ($arr_name: ident, $count: ident,) => {};
}

/// Test a block of nasl code line by line.
/// Optionally compare the results of each line
/// against a pattern. This macro allows specifying
/// a particular context to run the lines of code with.
/// Example usage:
/// ```
/// nasl_test_custom! {
///   context,
///   "foo = 5;" == 5,
///   "foo = 2;",
///   "foo = bar();" throws MissingArguments { .. },
/// }
/// ```
#[macro_export]
macro_rules! nasl_test_custom_context {
    ($context: expr, $($tt: tt)*) => {
        let mut code = vec![];
        $crate::_internal_nasl_test_code!(code, $($tt)*);
        let code = code.join("\n");
        let results = $crate::test_utils::run_custom_context(&code, $context);
        let mut _count = 0;
        $crate::_internal_nasl_test_expr!(results, _count, $($tt)*);
    }
}

/// Test a block of nasl code line by line.
/// Optionally compare the results of each line
/// against a pattern.
/// Example usage:
/// ```
/// nasl_test! {
///   "foo = 5;" == 5,
///   "foo = 2;",
///   "foo = bar();" throws MissingArguments { .. },
/// }
/// ```
#[macro_export]
macro_rules! nasl_test {
    ($($tt: tt)*) => {
        $crate::nasl_test_custom_context!($crate::ContextFactory::default(), $($tt)*);
    }
}
