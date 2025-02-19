use futures::{stream, Stream};

use crate::nasl::{
    syntax::{Lexer, Tokenizer},
    Context, NaslValue, Register,
};

use super::{interpreter::InterpretResult, interpreter::Interpreter};

pub struct ForkingInterpreter<'code, 'ctx> {
    _context: &'ctx Context<'ctx>,
    interpreters: Vec<Interpreter<'code>>,
    interpreter_index: usize,
}

impl<'code, 'ctx> ForkingInterpreter<'code, 'ctx> {
    pub fn new(code: &'code str, register: Register, context: &'ctx Context<'ctx>) -> Self {
        let tokenizer = Tokenizer::new(code);
        let lexer = Lexer::new(tokenizer);
        let interpreters = vec![Interpreter::new(register, lexer)];
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
        while !self.interpreters.is_empty() {
            let next_result = self.try_next().await;
            if next_result.is_some() {
                return next_result;
            }
        }
        None
    }

    async fn try_next(&mut self) -> Option<InterpretResult> {
        self.interpreter_index = (self.interpreter_index + 1) % self.interpreters.len();
        let result = self.interpreters[self.interpreter_index].execute_next_statement();
        if let Some(Ok(NaslValue::Fork(v))) = result {
            return Some(self.handle_fork(v));
        }
        result
    }

    fn handle_fork(&mut self, values: Vec<NaslValue>) -> InterpretResult {
        // TODO check that we are on root interpreter (if its necessary)
        let active_interpreter = &self.interpreters[self.interpreter_index];
        if values.is_empty() {
            return Ok(NaslValue::Null);
        }
        let forks: Vec<_> = values
            .into_iter()
            .map(|val| active_interpreter.make_fork(val))
            .collect();
        self.interpreters.extend(forks);
        todo!()
    }
}
