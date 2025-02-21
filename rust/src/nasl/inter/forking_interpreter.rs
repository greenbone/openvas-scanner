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
        dbg!(self.interpreter_index);
        let (state, interpreter) = &mut self.interpreters[self.interpreter_index];
        if *state == InterpreterState::Running {
            let result = interpreter.execute_next_statement().await;
            if let Some(Ok(NaslValue::Fork(v))) = result {
                return Some(self.handle_fork(v));
            }
            if result.is_none() {
                *state = InterpreterState::Finished;
            }
            result
        } else {
            None
        }
    }

    fn handle_fork(&mut self, mut values: Vec<NaslValue>) -> InterpretResult {
        // TODO check that we are on root interpreter (if its necessary)
        let (_, active_interpreter) = &self.interpreters[self.interpreter_index];
        if values.is_empty() {
            return Ok(NaslValue::Null);
        }
        let local_val = values.remove(0);
        let forks: Vec<_> = values
            .into_iter()
            .map(|val| active_interpreter.make_fork(val))
            .collect();
        self.interpreters.extend(forks);
        Ok(local_val)
    }
}

#[cfg(test)]
mod tests {
    use crate::nasl::{nasl_std_functions, test_prelude::*};

    #[test]
    fn forked_interpreter_statements() {
        let mut t = TestBuilder::default();
        t.run_all(
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
        let mut results = t.results();
        let mut next_result = || results.remove(0).unwrap();
        assert_eq!(next_result(), NaslValue::Null);
        assert_eq!(next_result(), NaslValue::Null);
        assert_eq!(
            next_result(),
            NaslValue::Return(Box::new(NaslValue::Number(3)))
        );
        assert_eq!(
            next_result(),
            NaslValue::Return(Box::new(NaslValue::Number(4)))
        );
        assert!(results.is_empty());
    }

    #[test]
    fn forked_interpreter_with_trailing_statements() {
        let mut t = TestBuilder::default();
        t.run_all(
            r#"
        set_kb_item(name: "test", value: 1);
        set_kb_item(name: "test", value: 2);
        if (get_kb_item("test") == 1) {
            return 3;
        }
        else {
        }
        return 4;
        "#,
        );
        let mut results = t.results();
        let mut next_result = || results.remove(0).unwrap();
        assert_eq!(next_result(), NaslValue::Null);
        assert_eq!(next_result(), NaslValue::Null);
        assert_eq!(
            next_result(),
            NaslValue::Return(Box::new(NaslValue::Number(3)))
        );
        assert_eq!(
            next_result(),
            NaslValue::Return(Box::new(NaslValue::Number(4)))
        );
        assert!(results.is_empty());
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
        let mut results = t.results();
        let mut next_result = || results.remove(0).unwrap();
        assert_eq!(next_result(), NaslValue::Null);
        assert_eq!(next_result(), NaslValue::Null);
        assert_eq!(
            next_result(),
            NaslValue::Return(Box::new(NaslValue::Number(1)))
        );
        assert_eq!(
            next_result(),
            NaslValue::Return(Box::new(NaslValue::Number(2)))
        );
        assert!(results.is_empty());
    }
}
