// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Utilities to test the outcome of NASL functions

use std::{
    fmt::{self, Display, Formatter},
    panic::Location,
};

use crate::storage::ContextKey;
use crate::{
    nasl::{
        prelude::*,
        syntax::{Loader, NoOpLoader},
    },
    storage::{DefaultDispatcher, Storage},
};
use futures::{Stream, StreamExt};

use super::{
    builtin::ContextFactory,
    interpreter::{CodeInterpreter, InterpretErrorKind},
    utils::Executor,
};

// The following exists to trick the trait solver into
// believing me that everything is fine. Doing this naively
// runs into some compiler errors.
trait CloneableFn: Fn(&NaslResult) -> bool + Sync + Send {
    fn clone_box<'a>(&self) -> Box<dyn 'a + CloneableFn>
    where
        Self: 'a;
}

impl<F> CloneableFn for F
where
    F: Fn(&NaslResult) -> bool + Clone + Sync + Send,
{
    fn clone_box<'a>(&self) -> Box<dyn 'a + CloneableFn>
    where
        Self: 'a,
    {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn '_ + CloneableFn> {
    fn clone(&self) -> Self {
        (**self).clone_box()
    }
}

#[derive(Clone)]
struct CodeLocation {
    file: String,
    line: u32,
    col: u32,
}

impl CodeLocation {
    fn new(location: &Location) -> Self {
        Self {
            file: location.file().to_string(),
            line: location.line(),
            col: location.column(),
        }
    }
}

impl Display for CodeLocation {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.file, self.line, self.col)
    }
}

/// A `TestResult` together with information
/// about where this particular test originates.
/// The location information exists in order to provide
/// better error messages.
#[derive(Clone)]
struct TracedTestResult {
    location: CodeLocation,
    result: TestResult,
}

impl From<TestResult> for TracedTestResult {
    #[track_caller]
    fn from(result: TestResult) -> Self {
        Self {
            result,
            location: CodeLocation::new(Location::caller()),
        }
    }
}

/// Contains the desired result of a line of
/// NASL code.
#[derive(Clone)]
enum TestResult {
    /// Expect the Result to be `Ok(val)` and compare `val` against a
    /// given `NaslValue`
    Ok(NaslValue),
    /// Performs a check described by the closure. To still provide
    /// decent error messages, the second argument may contain a
    /// String describing the expected result.
    GenericCheck(Box<dyn CloneableFn>, Option<String>),
    /// Do not perform any check.
    None,
}

/// A helper struct for quickly building tests of NASL functions.
/// Lines of NASL code can be added to the `TestBuilder` one by one,
/// and the context with which the code should be executed
/// can be set up as needed.
/// If the `TestBuilder` is dropped, it will automatically verify that
/// the given code fulfill the requirements (such as producing the right
/// values or the right errors).
pub struct TestBuilder<L: Loader, S: Storage> {
    lines: Vec<String>,
    results: Vec<TracedTestResult>,
    context: ContextFactory<L, S>,
    context_key: ContextKey,
    variables: Vec<(String, NaslValue)>,
    should_verify: bool,
}

pub type DefaultTestBuilder = TestBuilder<NoOpLoader, DefaultDispatcher>;

impl Default for TestBuilder<NoOpLoader, DefaultDispatcher> {
    fn default() -> Self {
        Self {
            lines: vec![],
            results: vec![],
            context: ContextFactory::default(),
            context_key: ContextKey::default(),
            variables: vec![],
            should_verify: true,
        }
    }
}

impl TestBuilder<NoOpLoader, DefaultDispatcher> {
    /// Construct a `TestBuilder`, immediately run the
    /// given code on it and return it.
    pub fn from_code(code: impl AsRef<str>) -> Self {
        let mut t = Self::default();
        t.run_all(code.as_ref());
        t
    }
}

impl<L, S> TestBuilder<L, S>
where
    L: Loader,
    S: Storage,
{
    #[track_caller]
    fn add_line(&mut self, line: impl Into<String>, val: TestResult) -> &mut Self {
        self.lines.push(line.into());
        self.results.push(val.into());
        self
    }

    /// Check that a `line` of NASL code results in `val`.
    /// ```rust
    /// # use crate::nasl::interpreter::test_utils::TestBuilder;
    /// let mut t = TestBuilder::default();
    /// t.ok("x = 3;", 3);
    /// ```
    #[track_caller]
    pub fn ok(&mut self, line: impl Into<String>, val: impl ToNaslResult) -> &mut Self {
        self.add_line(line, TestResult::Ok(val.to_nasl_result().unwrap()))
    }

    /// Perform an arbitrary check on a `line` of NASL code. The check
    /// is given by a closure that takes the result of the line of code
    /// and returns a bool. If the return value of the predicate is false,
    /// the test will panic.
    /// ```rust
    /// # use crate::nasl::interpreter::test_utils::TestBuilder;
    /// # use crate::nasl::interpreter::NaslValue;
    /// let mut t = TestBuilder::default();
    /// t.check("x = 3;", |x| matches!(x, Ok(NaslValue::Number(3))));
    /// ```
    #[track_caller]
    pub fn check(
        &mut self,
        line: impl Into<String>,
        f: impl Fn(&NaslResult) -> bool + 'static + Clone + Sync + Send,
        expected: Option<impl Into<String>>,
    ) -> &mut Self {
        self.add_line(
            line,
            TestResult::GenericCheck(Box::new(f), expected.map(|s| s.into())),
        )
    }

    /// Run a `line` of NASL code without checking its result.
    #[track_caller]
    pub fn run(&mut self, line: impl Into<String>) -> &mut Self {
        self.add_line(line, TestResult::None)
    }

    /// Run multiple lines of NASL code. If this method is called
    /// the test builder will not perform any checks on the given
    /// lines of code anymore (and will panic if any checks are
    /// added). This is mostly useful in combination with `results`
    /// if one wants to perform custom checks on the results returned
    /// by the code.
    pub fn run_all(&mut self, arg: impl Into<String>) {
        self.lines.push(arg.into());
        self.should_verify = false;
    }

    /// Return the list of results returned by all the lines of
    /// code.
    pub fn results(&self) -> Vec<NaslResult> {
        futures::executor::block_on(async {
            self.results_stream(&self.code(), &self.context())
                .collect()
                .await
        })
    }

    fn code(&self) -> String {
        self.lines.join("\n")
    }

    pub fn results_stream<'a>(
        &'a self,
        code: &'a str,
        context: &'a Context,
    ) -> impl Stream<Item = NaslResult> + 'a {
        let variables: Vec<_> = self
            .variables
            .iter()
            .map(|(k, v)| (k.clone(), ContextType::Value(v.clone())))
            .collect();
        let register = Register::root_initial(&variables);
        // let code = self.lines.join("\n");
        // let context = self.context();

        let parser = CodeInterpreter::new(code, register, context);
        parser.stream().map(|res| {
            res.map_err(|e| match e.kind {
                InterpretErrorKind::FunctionCallError(f) => f.kind,
                e => panic!("Unknown error: {}", e),
            })
        })
    }

    /// Get the currently set `Context`.
    pub fn context(&self) -> Context {
        self.context.build(self.context_key.clone())
    }

    /// Check that no errors were returned by any
    /// of the lines of code added to the `TestBuilder`.
    pub fn check_no_errors(&self) {
        for result in self.results() {
            if result.is_err() {
                panic!("Expected no errors, found {:?}", result);
            }
        }
    }

    async fn verify(&mut self) -> Result<(), String> {
        if self.should_verify {
            let mut references_iter = self.results.iter().enumerate();
            let code = self.code();
            let context = self.context();
            let mut results = self.results_stream(&code, &context);
            while let Some(result) = results.next().await {
                let (line_count, reference) = references_iter.next().unwrap();
                self.check_result(&result, reference, line_count)?;
            }
            assert!(references_iter.next().is_none());
        } else {
            // Make sure the user did not add requirements to this test
            // since we wont verify them. Panic if they did
            if self
                .results
                .iter()
                .any(|res| !matches!(res.result, TestResult::None))
            {
                return Err("Take care: Will not verify specified test result in this test, since run_all was called, which will mess with the line numbers.".to_string());
            }
        }
        Ok(())
    }

    pub async fn async_verify(mut self) {
        if let Err(err) = self.verify().await {
            // Drop first so we don't call the destructor, which would panic.
            std::mem::forget(self);
            panic!("{}", err)
        } else {
            std::mem::forget(self)
        }
    }

    fn check_result(
        &self,
        result: &Result<NaslValue, FnError>,
        reference: &TracedTestResult,
        line_count: usize,
    ) -> Result<(), String> {
        if !self.compare_result(result, &reference.result) {
            match &reference.result {
                TestResult::Ok(reference_result) => {
                    Err(format!(
                        "Mismatch at {}.\nIn code \"{}\":\nExpected: {:?}\nFound:    {:?}",
                        reference.location,
                        self.lines[line_count],
                        Ok::<_, FnError>(reference_result),
                        result,
                    ))?;
                }
                TestResult::GenericCheck(_, expected) => match expected {
                    Some(expected) => Err(format!(
                        "Mismatch at {}.\nIn code \"{}\":\nExpected: {}\nFound:    {:?}",
                        reference.location, self.lines[line_count], expected, result
                    ))?,
                    None => Err(format!(
                        "Check failed at {}.\nIn code \"{}\". Found result: {:?}",
                        reference.location, self.lines[line_count], result
                    ))?,
                },
                TestResult::None => unreachable!(),
            }
        }
        Ok(())
    }

    fn compare_result(&self, result: &Result<NaslValue, FnError>, reference: &TestResult) -> bool {
        match reference {
            TestResult::Ok(val) => result.as_ref().unwrap() == val,
            TestResult::GenericCheck(f, _) => f(result),
            TestResult::None => true,
        }
    }

    /// Return a new `TestBuilder` with the given `Context`.
    pub fn with_context<L2: Loader, S2: Storage>(
        self,
        context: ContextFactory<L2, S2>,
    ) -> TestBuilder<L2, S2> {
        TestBuilder {
            lines: self.lines.clone(),
            results: self.results.clone(),
            should_verify: self.should_verify,
            variables: self.variables.clone(),
            context,
            context_key: self.context_key.clone(),
        }
    }

    /// Return a new `TestBuilder` with the given `ContextKey`.
    pub fn with_context_key(mut self, key: ContextKey) -> Self {
        self.context_key = key;
        self
    }

    /// Return a new `TestBuilder` with the given `Executor`.
    pub fn with_executor(mut self, executor: Executor) -> Self {
        self.context.functions = executor;
        self
    }

    /// Set the variable with name `arg` to the given `value`
    pub fn set_variable(&mut self, arg: &str, value: NaslValue) {
        self.variables.push((arg.to_string(), value));
    }
}

impl<L: Loader, S: Storage> Drop for TestBuilder<L, S> {
    fn drop(&mut self) {
        if tokio::runtime::Handle::try_current().is_ok() {
            panic!("To use TestBuilder in an asynchronous context, explicitly call async_verify()");
        } else if let Err(err) = futures::executor::block_on(self.verify()) {
            panic!("{}", err)
        }
    }
}

/// Check that the value returned from a line of NASL code is
/// Ok(...) and that the inner value is equal to the expected
/// value. This is a convenience function to check single lines
/// of code that require no state.
#[track_caller]
pub fn check_code_result(code: &str, expected: impl ToNaslResult) {
    let mut test_builder = TestBuilder::default();
    test_builder.ok(code, expected);
}

/// Check that the line of NASL code returns an Err variant
/// and that the inner error matches a pattern.
/// If the first argument is a `TestBuilder`
/// the line is executed in the given builder.
/// Otherwise (that is, if only two arguments are given),
/// perform a check on the line of code using a new `TestBuilder`.
#[macro_export]
macro_rules! check_err_matches {
    ($t: ident, $code: expr, $pat: pat $(,)?) => {
        $t.check(
            $code,
            |e| {
                if let Err(e) = e {
                    // Convert with try_into to allow using
                    // the variants of `FnErrorKind` directly without
                    // having to wrap them in the outer enum.
                    let converted = e.try_into();
                    // This is only irrefutable for the
                    // FnError -> FnError conversion but not for others.
                    #[allow(irrefutable_let_patterns)]
                    if let Ok(e) = converted {
                        matches!(e, &$pat)
                    } else {
                        false
                    }
                } else {
                    false
                }
            },
            Some(stringify!($pat)),
        );
    };
    ($code: expr, $pat: pat $(,)?) => {
        let mut t = $crate::nasl::test_utils::TestBuilder::default();
        check_err_matches!(t, $code, $pat);
    };
}

/// Check that the line of NASL code returns an Ok variant
/// and that the inner value matches a pattern.
#[macro_export]
macro_rules! check_code_result_matches {
    ($code: expr, $pat: pat) => {
        let mut t = $crate::nasl::test_utils::TestBuilder::default();
        t.check($code, |val| matches!(val, Ok($pat)), Some(stringify!($pat)));
    };
}
