//! Utilities to test the outcome of NASL functions

use crate::*;
use futures::StreamExt;
use nasl_builtin_utils::{function::ToNaslResult, NaslResult};
use storage::Storage;

enum TestResult {
    Ok(NaslValue),
    GenericCheck(Box<dyn Fn(NaslResult) -> bool>),
    None,
}

/// TODO doc
pub struct TestBuilder<L: Loader, S: Storage> {
    lines: Vec<String>,
    results: Vec<TestResult>,
    context: ContextFactory<L, S>,
}

impl Default for TestBuilder<nasl_syntax::NoOpLoader, storage::DefaultDispatcher> {
    fn default() -> Self {
        Self {
            lines: vec![],
            results: vec![],
            context: ContextFactory::default(),
        }
    }
}

impl<L, S> TestBuilder<L, S>
where
    L: nasl_syntax::Loader,
    S: storage::Storage,
{
    fn add_line(&mut self, line: &str, val: TestResult) -> &mut Self {
        self.lines.push(line.to_string());
        self.results.push(val);
        self
    }

    /// TODO doc
    pub fn ok(&mut self, line: &str, val: impl ToNaslResult) -> &mut Self {
        self.add_line(line, TestResult::Ok(val.to_nasl_result().unwrap()))
    }

    /// TODO doc
    pub fn check(&mut self, line: &str, f: impl Fn(NaslResult) -> bool + 'static) -> &mut Self {
        self.add_line(line, TestResult::GenericCheck(Box::new(f)))
    }

    /// TODO doc
    pub fn run(&mut self, line: &str) -> &mut Self {
        self.add_line(line, TestResult::None)
    }

    fn verify(&mut self) {
        let code = self.lines.join("\n");
        let register = Register::default();
        let context = self.context.build(Default::default());

        let parser = CodeInterpreter::new(&code, register, &context);
        let results: Vec<_> = futures::executor::block_on(async {
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
        });
        assert_eq!(results.len(), self.results.len());
        for (line_count, (result, reference)) in
            (results.iter().zip(self.results.iter())).enumerate()
        {
            self.check_result(result, reference, line_count);
        }
    }

    fn check_result(
        &self,
        result: &Result<NaslValue, FunctionErrorKind>,
        reference: &TestResult,
        line_count: usize,
    ) {
        if !self.compare_result(result, reference) {
            match reference {
                TestResult::Ok(reference) => {
                    panic!(
                        "Mismatch in line {} with code \"{}\". Expected '{:?}', found '{:?}'",
                        line_count, self.lines[line_count], reference, result,
                    );
                }
                TestResult::GenericCheck(_) => todo!(),
                TestResult::None => unreachable!(),
            }
        }
    }

    fn compare_result(
        &self,
        result: &Result<NaslValue, FunctionErrorKind>,
        reference: &TestResult,
    ) -> bool {
        match reference {
            TestResult::Ok(val) => result.as_ref() == Ok(val),
            TestResult::GenericCheck(f) => f(result.clone()),
            TestResult::None => true,
        }
    }
}

impl<L: Loader, S: Storage> Drop for TestBuilder<L, S> {
    fn drop(&mut self) {
        self.verify()
    }
}

/// Check that the value returned from a line of NASL code is
/// Ok(...) and that the inner value is equal to the expected
/// value.
pub fn check_ok(code: &str, expected: impl ToNaslResult) {
    let mut test_builder = TestBuilder::default();
    test_builder.ok(code, expected);
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
    ($t: ident, $code: literal, $pat: pat $(,)?) => {
        $t.check($code, |e| matches!(e, Err($pat)));
    };
    ($code: literal, $pat: pat $(,)?) => {
        let mut t = $crate::test_utils::TestBuilder::default();
        t.check($code, |e| matches!(e, Err($pat)));
    };
}

/// Check that the line of NASL code returns an Ok variant
/// and that the inner value matches a pattern.
#[macro_export]
macro_rules! check_ok_matches {
    ($code: literal, $pat: pat) => {
        let mut t = $crate::test_utils::TestBuilder::default();
        t.check($code, |val| matches!(val, Ok($pat)));
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
