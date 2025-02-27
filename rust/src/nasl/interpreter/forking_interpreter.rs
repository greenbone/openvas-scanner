use futures::{stream, Stream};

use crate::nasl::{
    syntax::{Lexer, Tokenizer},
    Context, NaslValue, Register,
};

use super::{interpreter::InterpretResult, interpreter::Interpreter};

#[derive(PartialEq, Eq)]
pub enum InterpreterState {
    Running,
    Finished,
}

impl InterpreterState {
    fn is_finished(&self) -> bool {
        matches!(self, Self::Finished)
    }
}

pub struct ForkingInterpreter<'code, 'ctx> {
    _context: &'ctx Context<'ctx>,
    interpreters: Vec<(InterpreterState, Interpreter<'code, 'ctx>)>,
    interpreter_index: usize,
}

impl<'code, 'ctx> ForkingInterpreter<'code, 'ctx> {
    pub fn new(code: &'code str, register: Register, context: &'ctx Context<'ctx>) -> Self {
        let tokenizer = Tokenizer::new(code);
        let lexer = Lexer::new(tokenizer);
        let interpreters = vec![(
            InterpreterState::Running,
            Interpreter::new(register, lexer, context),
        )];
        Self {
            _context: context,
            interpreters,
            interpreter_index: 0,
        }
    }

    pub fn stream(self) -> impl Stream<Item = InterpretResult> + 'code
    where
        'ctx: 'code,
    {
        Box::pin(stream::unfold(self, |mut s| async move {
            s.next().await.map(|x| (x, s))
        }))
    }

    pub fn iter_blocking(self) -> impl Iterator<Item = InterpretResult> {
        use futures::StreamExt;

        futures::executor::block_on(async { self.stream().collect::<Vec<_>>().await.into_iter() })
    }

    async fn next(&mut self) -> Option<InterpretResult> {
        while self
            .interpreters
            .iter()
            .any(|(state, _)| !state.is_finished())
        {
            let next_result = self.try_next().await;
            if next_result.is_some() {
                return next_result;
            }
        }
        None
    }

    async fn try_next(&mut self) -> Option<InterpretResult> {
        self.interpreter_index = (self.interpreter_index + 1) % self.interpreters.len();
        let (state, interpreter) = &mut self.interpreters[self.interpreter_index];
        if *state == InterpreterState::Running {
            let result = interpreter.execute_next_statement().await;
            if result.is_none() || matches!(result.as_ref().unwrap(), Ok(NaslValue::Exit(_))) {
                *state = InterpreterState::Finished;
            }
            if self.handle_forks() {
                None
            } else {
                result
            }
        } else {
            None
        }
    }

    fn handle_forks(&mut self) -> bool {
        // This check is not necessary, but otherwise we will
        // remove and re-insert the interpreter on every statement,
        // even if the statement does not create a fork, which
        // might cause performance issues.
        if self.interpreters[self.interpreter_index].1.should_fork() {
            let (_, interpreter) = self.interpreters.remove(self.interpreter_index);
            let forks = interpreter.create_forks();
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
}

#[cfg(test)]
mod tests {
    use crate::nasl::{
        interpreter::{InterpretError, InterpretErrorKind},
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
            get_kb_item("port") + ":" + get_kb_item("host");
            "#,
        );
        assert_eq!(
            t.values(),
            vec![
                NaslValue::Null,
                NaslValue::Null,
                NaslValue::Null,
                NaslValue::Null,
                "1:a".into(),
                "1:b".into(),
                "2:a".into(),
                "2:b".into(),
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
            Err(InterpretError {
                kind: InterpretErrorKind::InvalidFork,
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
