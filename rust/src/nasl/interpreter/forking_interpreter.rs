use futures::{Stream, stream};

use crate::nasl::{Register, ScanCtx, syntax::grammar::Ast};

use super::{Interpreter, Result};

/// Handles code execution with forking behavior.
/// In order to do so, this struct maintains a list of
/// `Interpreter`s. Whenever a statement that results
/// in a fork is executed, new interpreters will be added
/// for each of the forks.
pub struct ForkingInterpreter<'ctx> {
    interpreters: Vec<Interpreter<'ctx>>,
    interpreter_index: usize,
    ast: Ast,
}

impl<'ctx> ForkingInterpreter<'ctx> {
    pub fn new(ast: Ast, mut register: Register, context: &'ctx ScanCtx<'ctx>) -> Self {
        context.add_fn_global_vars(&mut register);
        let interpreters = vec![Interpreter::new(register, context)];
        Self {
            interpreters,
            interpreter_index: 0,
            ast,
        }
    }

    pub fn stream(self) -> impl Stream<Item = Result> + use<'ctx> {
        Box::pin(stream::unfold(self, |mut s| async move {
            s.next().await.map(|x| (x, s))
        }))
    }

    pub async fn execute_all(&mut self) -> Result<()> {
        while let Some(result) = self.next().await {
            result?;
        }
        Ok(())
    }

    pub fn iter_blocking(self) -> impl Iterator<Item = Result> + use<> {
        use futures::StreamExt;

        futures::executor::block_on(async { self.stream().collect::<Vec<_>>().await.into_iter() })
    }

    async fn next(&mut self) -> Option<Result> {
        while self
            .interpreters
            .iter()
            .any(|interpreter| !interpreter.is_finished())
        {
            let next_result = self.try_next().await;
            if next_result.is_some() {
                return next_result;
            }
        }
        None
    }

    /// Tries to execute a statement for the next running interpreter
    /// Returns `None` if the current interpreter is not running, or
    /// if the current interpreter wanted to fork (in which case we return
    /// `None` once but subsequent calls to `try_next` will begin executing
    /// the same statement for the forks).
    async fn try_next(&mut self) -> Option<Result> {
        self.interpreter_index = (self.interpreter_index + 1) % self.interpreters.len();
        let interpreter = &mut self.interpreters[self.interpreter_index];
        if !interpreter.is_finished() {
            let stmt = self.ast.get(interpreter.stmt_index);
            let result = interpreter.execute_statement(stmt).await;
            if self.create_forks_if_necessary() {
                None
            } else {
                result
            }
        } else {
            None
        }
    }

    /// Checks if the current interpreter wants to fork.
    /// If it does, it replaces the current interpreter by
    /// as many new interpreters as desired and returns `true`.
    /// Otherwise returns `false`.
    fn create_forks_if_necessary(&mut self) -> bool {
        // This check is not necessary, but otherwise we will
        // remove and re-insert the interpreter on every statement,
        // even if the statement does not create a fork, which
        // might cause performance issues.
        if self.interpreters[self.interpreter_index].wants_to_fork() {
            let interpreter = self.interpreters.remove(self.interpreter_index);
            let forks = interpreter.make_forks();
            // Insert the new interpreters in order and "in place", so
            // that the first fork has exactly the same position that the
            // interpreter which created the fork had previously.  This is
            // most likely very inefficient, but performance is of
            // secondary importance for now.
            let num_forks = forks.len();
            for (i, fork) in forks.into_iter().enumerate() {
                self.interpreters.insert(self.interpreter_index + i, fork);
            }
            // For consistency with previous behavior, make sure that the next interpreter
            // that advances is the one just behind the last newly inserted interpreter
            self.interpreter_index =
                (self.interpreter_index + num_forks - 1) % self.interpreters.len();
            true
        } else {
            false
        }
    }

    /// If there is only one interpreter, get its register.
    pub fn register(&self) -> &Register {
        &self.interpreters[0].register
    }
}

#[cfg(test)]
mod tests {
    use crate::nasl::{
        interpreter::{InterpreterError, InterpreterErrorKind},
        nasl_std_functions,
        test_prelude::*,
    };

    #[test]
    fn simple_fork() {
        let t = TestBuilder::from_code(
            r#"
            set_kb_item(name: "foo", value: 1);
            set_kb_item(name: "foo", value: 2);
            get_kb_item("foo");
            "#,
        );
        assert_eq!(
            t.values(),
            vec![NaslValue::Null, NaslValue::Null, 1.into(), 2.into()]
        );
    }

    #[test]
    fn fork_twice_on_same_item() {
        let t = TestBuilder::from_code(
            r#"
            set_kb_item(name: "a", value: 1);
            set_kb_item(name: "a", value: 2);
            set_kb_item(name: "a", value: 3);
            get_kb_item("a") + get_kb_item("a");
            "#,
        );
        assert_eq!(
            t.values(),
            vec![
                NaslValue::Null,
                NaslValue::Null,
                NaslValue::Null,
                2.into(),
                3.into(),
                4.into(),
                3.into(),
                4.into(),
                5.into(),
                4.into(),
                5.into(),
                6.into(),
            ]
        );
    }

    #[test]
    fn empty_fork() {
        let t = TestBuilder::from_code(
            r#"
            get_kb_item("port") + ":" + get_kb_item("host");
            "#,
        );
        assert_eq!(t.values(), vec!["\0:\0".into()]);
    }

    #[test]
    fn multiple_forks_on_one_line() {
        let t = TestBuilder::from_code(
            r#"
            set_kb_item(name: "port", value: 1);
            set_kb_item(name: "port", value: 2);
            set_kb_item(name: "host", value: "a");
            set_kb_item(name: "host", value: "b");
            get_kb_item("host") + ":" + get_kb_item("port");
            "#,
        );
        assert_eq!(
            t.values(),
            vec![
                NaslValue::Null,
                NaslValue::Null,
                NaslValue::Null,
                NaslValue::Null,
                "a:1".into(),
                "a:2".into(),
                "b:1".into(),
                "b:2".into(),
            ]
        );
    }

    #[test]
    fn simple_fork_condition() {
        let t = TestBuilder::from_code(
            r#"
            set_kb_item(name: "test", value: 1);
            set_kb_item(name: "test", value: 2);
            if (get_kb_item("test") == 1) {
                return 3;
            }
            else {
                return 4;
            }
            "#,
        );
        assert_eq!(
            t.values(),
            vec![
                NaslValue::Null,
                NaslValue::Null,
                NaslValue::Return(Box::new(NaslValue::Number(3))),
                NaslValue::Return(Box::new(NaslValue::Number(4)))
            ]
        );
    }

    #[test]
    fn forked_interpreter_with_trailing_statements() {
        let t = TestBuilder::from_code(
            r#"
            set_kb_item(name: "test", value: 1);
            set_kb_item(name: "test", value: 2);
            if (get_kb_item("test") == 1) {
                exit(3);
            }
            exit(4);
            "#,
        );
        assert_eq!(
            t.values(),
            vec![
                NaslValue::Null,
                NaslValue::Null,
                NaslValue::Exit(3),
                NaslValue::Null,
                NaslValue::Exit(4),
            ]
        );
    }

    #[test]
    fn multiple_forks() {
        let t = TestBuilder::from_code(
            r#"
            set_kb_item(name: "port", value: 1);
            set_kb_item(name: "port", value: 2);
            set_kb_item(name: "host", value: "a");
            set_kb_item(name: "host", value: "b");
            get_kb_item("port");
            get_kb_item("host");
            "#,
        );
        assert_eq!(
            t.values(),
            vec![
                NaslValue::Null,
                NaslValue::Null,
                NaslValue::Null,
                NaslValue::Null,
                1.into(),
                2.into(),
                "a".into(),
                "b".into(),
                "a".into(),
                "b".into(),
            ]
        );
    }

    #[test]
    fn forks_with_different_branches() {
        let t = TestBuilder::from_code(
            r#"
            set_kb_item(name: "test1", value: 1);
            set_kb_item(name: "test1", value: 2);
            set_kb_item(name: "test2", value: 3);
            set_kb_item(name: "test2", value: 4);
            set_kb_item(name: "test3", value: 5);
            set_kb_item(name: "test3", value: 6);
            if (get_kb_item("test1") == 1) {
                get_kb_item("test2");
            }
            else {
                get_kb_item("test3");
            }
            "#,
        );
        let mut results = t.interpreter_results();
        for _ in 0..6 {
            assert_eq!(results.remove(0).unwrap(), NaslValue::Null);
        }
        // Advancing the iterator into the if statement
        // should return an error.
        match results.remove(0) {
            Err(InterpreterError {
                kind: InterpreterErrorKind::InvalidFork,
                ..
            }) => {}
            _ => panic!(),
        }
    }

    #[test]
    fn exit_ends_execution() {
        let t = TestBuilder::from_code(
            r#"
            exit(1);
            2;
            "#,
        );
        assert_eq!(t.values(), vec![NaslValue::Exit(1)]);
    }

    struct MySet(usize);

    impl MySet {
        #[nasl_function]
        fn rand_sim(&mut self) -> usize {
            self.0 += 1;
            self.0 - 1
        }
    }

    function_set! {
        MySet,
        (
            (MySet::rand_sim, "rand_sim"),
        )
    }

    #[test]
    fn forked_interpreter_with_nondeterministic_behavior() {
        let mut exec = nasl_std_functions();
        exec.add_set(MySet(0));
        let mut t = TestBuilder::default().with_executor(exec);
        t.run_all(
            r#"
            set_kb_item(name: "test", value: 1);
            set_kb_item(name: "test", value: 2);
            if (rand_sim() == 0) {
                x = "foo"; # Noop statement to make sure we don't accidentally do the right thing
                return get_kb_item("test");
            }
            else {
                return 3;
            }
        "#,
        );
        assert_eq!(
            t.values(),
            vec![
                NaslValue::Null,
                NaslValue::Null,
                NaslValue::Return(Box::new(NaslValue::Number(1))),
                NaslValue::Return(Box::new(NaslValue::Number(2)))
            ]
        );
    }
}
