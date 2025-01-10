// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Contains implementations of Interpreter that handle the simulation of forking methods for the
//! caller.

use futures::{stream, Stream};

use crate::nasl::syntax::{Lexer, Statement, Tokenizer};

use crate::nasl::interpreter::interpreter::{InterpretResult, Interpreter};
use crate::nasl::prelude::*;

/// Uses given code to return results based on that.
pub struct CodeInterpreter<'a, 'b> {
    lexer: Lexer<'b>,
    interpreter: Interpreter<'a>,
    statement: Option<Statement>,
}

impl<'a, 'b> CodeInterpreter<'a, 'b> {
    /// Creates a new code interpreter
    pub fn new(
        code: &'b str,
        register: Register,
        context: &'a Context<'a>,
    ) -> CodeInterpreter<'a, 'b> {
        let token = Tokenizer::new(code);
        let lexer = Lexer::new(token);
        let interpreter = Interpreter::new(register, context);
        Self {
            lexer,
            interpreter,
            statement: None,
        }
    }

    /// Evaluates the next statement
    pub async fn next_statement(&mut self) -> Option<InterpretResult> {
        self.statement = None;
        match self.lexer.next() {
            Some(Ok(nstmt)) => {
                let results = Some(self.interpreter.retry_resolve_next(&nstmt, 5).await);
                self.statement = Some(nstmt);
                results
            }
            Some(Err(err)) => Some(Err(err.into())),
            None => None,
        }
    }

    async fn next_(&mut self) -> Option<InterpretResult> {
        if let Some(stmt) = self.statement.as_ref() {
            match self.interpreter.next_interpreter() {
                Some(inter) => Some(inter.retry_resolve(stmt, 5).await),
                None => self.next_statement().await,
            }
        } else {
            self.next_statement().await
        }
    }

    /// Creates a stream over the results of the statements
    pub fn stream(self) -> impl Stream<Item = InterpretResult> + 'b
    where
        'a: 'b,
    {
        Box::pin(stream::unfold(self, |mut s| async move {
            s.next_().await.map(|x| (x, s))
        }))
    }

    /// Blocks on the results of the stream.
    #[cfg(test)]
    pub fn iter_blocking(self) -> impl Iterator<Item = InterpretResult> + 'b
    where
        'a: 'b,
    {
        use futures::StreamExt;

        futures::executor::block_on(async { self.stream().collect::<Vec<_>>().await.into_iter() })
    }

    /// Returns the Register of the underlying Interpreter
    pub fn register(&self) -> &Register {
        self.interpreter.register()
    }
}

#[cfg(test)]
mod tests {
    use crate::nasl::test_prelude::*;

    #[test]
    fn code_interpreter() {
        check_code_result(r#"set_kb_item(name: "test", value: 1);"#, NaslValue::Null);
        check_code_result(r#"set_kb_item(name: "test", value: 2);"#, NaslValue::Null);
        check_code_result(r#"display(get_kb_item("test"));"#, NaslValue::Null);
    }
}
