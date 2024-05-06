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
                    .retry_resolve(&self.statement, self.retries),
            )
        } else {
            self.interpreter
                .next_interpreter()
                .map(|i| i.retry_resolve(&self.statement, self.retries))
        }
    }
}
