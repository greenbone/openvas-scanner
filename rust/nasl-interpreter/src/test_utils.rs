//! Utilities to test the outcome of NASL functions

use crate::*;
use futures::StreamExt;
use nasl_builtin_utils::{function::ToNaslResult, NaslResult};
use storage::Storage;

// The following exists to trick the trait solver into
// believing me that everything is fine. Doing this naively
// runs into some compiler errors
trait CloneableFn: Fn(NaslResult) -> bool {
    fn clone_box<'a>(&self) -> Box<dyn 'a + CloneableFn>
    where
        Self: 'a;
}

impl<F> CloneableFn for F
where
    F: Fn(NaslResult) -> bool + Clone,
{
    fn clone_box<'a>(&self) -> Box<dyn 'a + CloneableFn>
    where
        Self: 'a,
    {
        Box::new(self.clone())
    }
}

impl<'a> Clone for Box<dyn 'a + CloneableFn> {
    fn clone(&self) -> Self {
        (**self).clone_box()
    }
}

#[derive(Clone)]
enum TestResult {
    Ok(NaslValue),
    GenericCheck(Box<dyn CloneableFn>),
    None,
}

/// TODO doc
pub struct TestBuilder<L: Loader, S: Storage> {
    lines: Vec<String>,
    results: Vec<TestResult>,
    context: ContextFactory<L, S>,
    should_verify: bool,
}

impl Default for TestBuilder<nasl_syntax::NoOpLoader, storage::DefaultDispatcher> {
    fn default() -> Self {
        Self {
            lines: vec![],
            results: vec![],
            context: ContextFactory::default(),
            should_verify: true,
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
    pub fn check(
        &mut self,
        line: &str,
        f: impl Fn(NaslResult) -> bool + 'static + Clone,
    ) -> &mut Self {
        self.add_line(line, TestResult::GenericCheck(Box::new(f)))
    }

    /// TODO doc
    pub fn run(&mut self, line: &str) -> &mut Self {
        self.add_line(line, TestResult::None)
    }

    /// TODO doc
    pub fn run_all(&mut self, arg: &str) {
        self.lines.push(arg.to_string());
        self.should_verify = false;
    }

    /// TODO doc
    pub fn results(&self) -> Vec<NaslResult> {
        let code = self.lines.join("\n");
        let register = Register::default();
        let context = self.context.build(Default::default());

        let parser = CodeInterpreter::new(&code, register, &context);
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

    fn verify(&mut self) {
        let results = self.results();
        if self.should_verify {
            assert_eq!(results.len(), self.results.len());
            for (line_count, (result, reference)) in
                (results.iter().zip(self.results.iter())).enumerate()
            {
                self.check_result(result, reference, line_count);
            }
        } else {
            // Make sure the user did not add requirements to this test
            // since we wont verify them. Panic if they did
            if self
                .results
                .iter()
                .any(|res| !matches!(res, TestResult::None))
            {
                panic!("Take care: Will not verify specified test result in this test, since run_all was called, which will mess with the line numbers.");
            }
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
                TestResult::GenericCheck(_) => {
                    panic!(
                        "Check failed in line {} with code \"{}\".",
                        line_count, self.lines[line_count]
                    );
                }
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

    /// TODO doc
    pub fn with_context<L2: Loader, S2: Storage>(
        self,
        context: ContextFactory<L2, S2>,
    ) -> TestBuilder<L2, S2> {
        TestBuilder {
            lines: self.lines.clone(),
            results: self.results.clone(),
            should_verify: self.should_verify,
            context: context,
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
