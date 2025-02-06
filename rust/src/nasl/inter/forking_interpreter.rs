use futures::{stream, Stream};

use crate::nasl::{
    syntax::{Lexer, Tokenizer},
    Context, Register,
};

use super::{interpreter::InterpretResult, interpreter::Interpreter};

pub struct ForkingInterpreter<'code, 'ctx> {
    _context: &'ctx Context<'ctx>,
    _lexer: Lexer<'code>,
    _interpreters: Vec<Interpreter>,
}

impl<'code, 'ctx> ForkingInterpreter<'code, 'ctx> {
    pub fn new(code: &'code str, register: Register, context: &'ctx Context<'ctx>) -> Self {
        let tokenizer = Tokenizer::new(code);
        let lexer = Lexer::new(tokenizer);
        let interpreters = vec![Interpreter::new(register)];
        Self {
            _context: context,
            _lexer: lexer,
            _interpreters: interpreters,
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
        todo!()
    }
}
