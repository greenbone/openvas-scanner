//! Contains implementations of Interpreter that handle the simulation of forking methods for the
//! caller.

use futures::{stream, Stream};

use nasl_syntax::Statement;

use crate::interpreter::InterpretResult;

/// To allow closures we use a heap stored statement consumer
type StatementConsumer = Box<dyn Fn(&Statement)>;

/// Uses given code to return results based on that.
pub struct CodeInterpreter<'a, 'b> {
    lexer: nasl_syntax::Lexer<'b>,
    interpreter: crate::interpreter::Interpreter<'a>,
    statement: Option<Statement>,
    /// call back function for Statements before they get interpreted
    pub statement_cb: Option<StatementConsumer>,
}

impl<'a, 'b> CodeInterpreter<'a, 'b> {
    /// Creates a new code interpreter
    ///
    /// Example:
    /// ```
    /// use nasl_syntax::NaslValue;
    /// use nasl_interpreter::{Register, ContextFactory , CodeInterpreter};
    /// let register = Register::default();
    /// let context_builder = ContextFactory ::default();
    /// let context = context_builder.build(Default::default());
    /// let code = r#"
    /// set_kb_item(name: "test", value: 1);
    /// set_kb_item(name: "test", value: 2);
    /// display(get_kb_item("test"));
    /// "#;
    /// let interpreter = CodeInterpreter::new(code, register, &context);
    /// let results = interpreter.filter_map(|x|x.ok()).collect::<Vec<_>>();
    /// assert_eq!(results, vec![NaslValue::Null; 4]);
    /// ```
    pub fn new(
        code: &'b str,
        register: crate::Register,
        context: &'a crate::Context<'a>,
    ) -> CodeInterpreter<'a, 'b> {
        let token = nasl_syntax::Tokenizer::new(code);
        let lexer = nasl_syntax::Lexer::new(token);
        let interpreter = crate::interpreter::Interpreter::new(register, context);
        Self {
            lexer,
            interpreter,
            statement: None,
            statement_cb: None,
        }
    }

    /// Creates a new code interpreter with a callback before a statement gets executed
    ///
    /// Example:
    /// ```
    /// use nasl_syntax::NaslValue;
    /// use nasl_interpreter::{Register, ContextFactory , CodeInterpreter};
    /// let register = Register::default();
    /// let context_builder = ContextFactory ::default();
    /// let context = context_builder.build(Default::default());
    /// let code = r#"
    /// set_kb_item(name: "test", value: 1);
    /// set_kb_item(name: "test", value: 2);
    /// display(get_kb_item("test"));
    /// "#;
    /// let interpreter = CodeInterpreter::with_statement_callback(code, register, &context, &|x|println!("{x}"));
    /// let results = interpreter.filter_map(|x|x.ok()).collect::<Vec<_>>();
    /// assert_eq!(results, vec![NaslValue::Null; 4]);
    /// ```
    pub fn with_statement_callback(
        code: &'b str,
        register: crate::Register,
        context: &'a crate::Context<'a>,
        cb: &'static dyn Fn(&Statement),
    ) -> CodeInterpreter<'a, 'b> {
        let mut result = Self::new(code, register, context);
        result.statement_cb = Some(Box::new(cb));
        result
    }

    /// TODO Doc
    pub async fn next_statement(&mut self) -> Option<InterpretResult> {
        self.statement = None;
        match self.lexer.next() {
            Some(Ok(nstmt)) => {
                if let Some(cb) = &self.statement_cb {
                    cb(&nstmt);
                }
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

    /// TODO Doc
    pub fn stream(self) -> impl Stream<Item = InterpretResult> + 'b
    where
        'a: 'b,
    {
        Box::pin(stream::unfold(self, |mut s| async move {
            let x = s.next_().await;
            if let Some(x) = x {
                Some((x, s))
            } else {
                None
            }
        }))
    }

    /// TODO Doc
    #[cfg(test)]
    pub fn iter_blocking(self) -> impl Iterator<Item = InterpretResult> + 'b
    where
        'a: 'b,
    {
        use futures::StreamExt;

        futures::executor::block_on(async { self.stream().collect::<Vec<_>>().await.into_iter() })
    }

    /// Returns the Register of the underlying Interpreter
    pub fn register(&self) -> &crate::Register {
        self.interpreter.register()
    }
}

impl<'a, 'b> Iterator for CodeInterpreter<'a, 'b> {
    type Item = InterpretResult;

    fn next(&mut self) -> Option<Self::Item> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use nasl_syntax::NaslValue;

    use crate::{nasl_test, nasl_test_internal_code, nasl_test_internal_expr};

    #[test]
    fn code_interpreter() {
        nasl_test! {
            r#"set_kb_item(name: "test", value: 1);"# == NaslValue::Null,
            r#"set_kb_item(name: "test", value: 2);"# == NaslValue::Null,
            r#"display(get_kb_item("test"));"# == NaslValue::Null,
        }
    }
}
