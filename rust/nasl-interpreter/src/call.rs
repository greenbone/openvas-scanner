use nasl_syntax::{
    Statement, Statement::*, Token,
};
use std::{ops::Range, collections::HashMap};


use crate::{interpreter::InterpretResult, Interpreter, context::NaslContextType, lookup, ContextType, error::InterpretError};

/// Is a trait to handle function calls within nasl.
pub(crate) trait CallExtension {
    /// Is the actual handling of postfix. The caller must ensure that needs_postfix is called previously.
    fn call(&mut self, name: Token, arguments: Box<Statement>) -> InterpretResult;
}

impl<'a> CallExtension for Interpreter<'a> {
    #[inline(always)]
    fn call(&mut self, name: Token, arguments: Box<Statement>) -> InterpretResult {
        let name = &self.code[Range::from(name)];
        // get the context
        let mut named = HashMap::new();
        let mut position = vec![];
        match *arguments{
            Parameter(params) => {
                for p in params {
                    match p {
                        NamedParameter(token, val) => {
                            let val = self.resolve(*val)?;
                            let name = self.code[Range::from(token)].to_owned();
                            named.insert(name, ContextType::Value(val));
                        }
                        val => {
                            let val = self.resolve(val)?;
                            position.push(ContextType::Value(val));
                        }
                    }
                }
            }
            _ => {
                return Err(InterpretError::new(
                    "invalid statement type for function parameters".to_string(),
                ))
            }
        };

        self.registrat
            .create_root_child(NaslContextType::Function(named, position));
        // TODO change to use root context to lookup both
        let result = match lookup(name) {
            // Built-In Function
            Some(function) => match function(self.resolve_key(), self.storage, &self.registrat) {
                Ok(value) => Ok(value),
                Err(x) => Err(InterpretError::new(format!(
                    "unable to call function {}: {:?}",
                    name, x
                ))),
            },
            // Check for user defined function
            None => todo!(
                "{} not a built-in function and user function are not yet implemented",
                name.to_string()
            ),
        };
        self.registrat.drop_last();
        result
    }
}
