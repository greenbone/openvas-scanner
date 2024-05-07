//! Contains implementations of Interpreter that handle the simulation of forking methods for the
//! caller.

use nasl_syntax::Statement;

use crate::interpreter::InterpretResult;

/// Iterates through all interpreter per Statement
pub struct StatementIterator<'a, 'b, K> {
    interpreter: &'b mut crate::interpreter::Interpreter<'a, K>,
    statement: Statement,
    retries: usize,
    first: bool,
}

impl<'a, 'b, K> StatementIterator<'a, 'b, K>
where
    K: AsRef<str>,
{
    /// Creates a new instance of StatementIterator
    ///
    /// Example:
    /// ```
    /// use nasl_syntax::NaslValue;
    /// use nasl_interpreter::{Interpreter, Register, ContextBuilder, StatementIterator};
    /// let register = Register::default();
    /// let context_builder = ContextBuilder::default();
    /// let context = context_builder.build();
    /// let code = r#"
    /// set_kb_item(name: "test", value: 1);
    /// set_kb_item(name: "test", value: 2);
    /// display(get_kb_item("test"));
    /// "#;
    /// let mut interpreter = Interpreter::new(register, &context);
    /// let mut results = vec![];
    /// for r in nasl_syntax::parse(code){
    ///     for r in StatementIterator::new(&mut interpreter, r.expect("parseable")) {
    ///         results.push(r.expect("executable"));
    ///     }
    /// }
    /// assert_eq!(results, vec![NaslValue::Null; 4]);
    /// ```
    pub fn new(
        inter: &'b mut crate::interpreter::Interpreter<'a, K>,
        statement: Statement,
    ) -> Self {
        Self {
            interpreter: inter,
            statement,
            retries: 5,
            first: true,
        }
    }
}

impl<'a, 'b, K> Iterator for StatementIterator<'a, 'b, K>
where
    K: AsRef<str>,
{
    type Item = InterpretResult;

    fn next(&mut self) -> Option<Self::Item> {
        if self.first {
            self.first = false;
            Some(
                self.interpreter
                    .retry_resolve_next(&self.statement, self.retries),
            )
        } else {
            self.interpreter
                .next_interpreter()
                .map(|i| i.retry_resolve(&self.statement, self.retries))
        }
    }
}

/// Uses given code to return results based on that.
pub struct CodeInterpreter<'a, 'b, K> {
    lexer: nasl_syntax::Lexer<'b>,
    interpreter: crate::interpreter::Interpreter<'a, K>,
    statement: Option<Statement>,
    /// call back function for Statements before they get interpret
    pub statemet_cb: Option<Box<dyn Fn(&Statement)>>,
}

impl<'a, 'b, K> CodeInterpreter<'a, 'b, K>
where
    K: AsRef<str>,
{
    /// Creates a new code interpreter
    ///
    /// Example:
    /// ```
    /// use nasl_syntax::NaslValue;
    /// use nasl_interpreter::{Register, ContextBuilder, CodeInterpreter};
    /// let register = Register::default();
    /// let context_builder = ContextBuilder::default();
    /// let context = context_builder.build();
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
        context: &'a crate::Context<'a, K>,
    ) -> CodeInterpreter<'a, 'b, K> {
        let token = nasl_syntax::Tokenizer::new(code);
        let lexer = nasl_syntax::Lexer::new(token);
        let interpreter = crate::interpreter::Interpreter::new(register, context);
        Self {
            lexer,
            interpreter,
            statement: None,
            statemet_cb: None,
        }
    }



    /// Creates a new code interpreter with a callback before a statement gets executed
    ///
    /// Example:
    /// ```
    /// use nasl_syntax::NaslValue;
    /// use nasl_interpreter::{Register, ContextBuilder, CodeInterpreter};
    /// let register = Register::default();
    /// let context_builder = ContextBuilder::default();
    /// let context = context_builder.build();
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
        context: &'a crate::Context<'a, K>,
        cb: &'static dyn Fn(&Statement),
    ) -> CodeInterpreter<'a, 'b, K> {
        let mut result = Self::new(code, register, context);
        result.statemet_cb = Some(Box::new(cb));
        result
    }

    fn next_statement(&mut self) -> Option<InterpretResult> {
        self.statement = None;
        match self.lexer.next() {
            Some(Ok(nstmt)) => {
                if let Some(cb) = &self.statemet_cb {
                    cb(&nstmt);
                }
                let results = Some(self.interpreter.retry_resolve_next(&nstmt, 5));
                self.statement = Some(nstmt);
                results
            }
            Some(Err(err)) => Some(Err(err.into())),
            None => None,
        }
    }

    /// Returns the Register of the underlying Interpreter
    pub fn register(&self) -> &crate::Register {
        self.interpreter.register()
    }
}

impl<'a, 'b, K> Iterator for CodeInterpreter<'a, 'b, K>
where
    K: AsRef<str>,
{
    type Item = InterpretResult;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(stmt) = self.statement.as_ref() {
            match self.interpreter.next_interpreter() {
                Some(inter) => Some(inter.retry_resolve(stmt, 5)),
                None => self.next_statement(),
            }
        } else {
            self.next_statement()
        }
    }
}

#[cfg(test)]
mod rests {
    #[test]
    fn code_interpreter() {
        use crate::{CodeInterpreter, ContextBuilder, Register};
        use nasl_syntax::NaslValue;
        let register = Register::default();
        let context_builder = ContextBuilder::default();
        let context = context_builder.build();
        let code = r#"
            set_kb_item(name: "test", value: 1);
            set_kb_item(name: "test", value: 2);
            display(get_kb_item("test"));
        "#;
        let interpreter = CodeInterpreter::with_statement_callback(code, register, &context, &|x|println!("{x}"));
        let results = interpreter.filter_map(|x| x.ok()).collect::<Vec<_>>();
        assert_eq!(results, vec![NaslValue::Null; 4]);
    }
}
