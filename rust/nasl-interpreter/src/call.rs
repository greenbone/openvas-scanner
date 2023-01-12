use nasl_syntax::{Statement, Statement::*, Token};

use crate::{
    error::InterpretError, interpreter::InterpretResult, lookup, ContextType, Interpreter,
    NaslValue,
};
use std::collections::HashMap;

/// Is a trait to handle function calls within nasl.
pub(crate) trait CallExtension {
    fn call(&mut self, name: Token, arguments: Box<Statement>) -> InterpretResult;
}

impl<'a> CallExtension for Interpreter<'a> {
    #[inline(always)]
    fn call(&mut self, name: Token, arguments: Box<Statement>) -> InterpretResult {
        let name = &Self::identifier(&name)?;
        // get the context
        let mut named = HashMap::new();
        let mut position = vec![];
        match *arguments {
            Parameter(params) => {
                for p in params {
                    match p {
                        NamedParameter(token, val) => {
                            let val = self.resolve(*val)?;
                            let name = Self::identifier(&token)?;
                            named.insert(name, ContextType::Value(val));
                        }
                        val => {
                            let val = self.resolve(val)?;
                            position.push(val);
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
        named.insert(
            "_FCT_ANON_ARGS".to_owned(),
            ContextType::Value(NaslValue::Array(position)),
        );
        self.registrat.create_root_child(named);
        let result = match lookup(name) {
            // Built-In Function
            Some(function) => match function(self.key, self.storage, self.registrat) {
                Ok(value) => Ok(value),
                Err(x) => Err(InterpretError::new(format!(
                    "unable to call function {}: {:?}",
                    name, x
                ))),
            },
            // Check for user defined function
            None => {
                let found = self
                    .registrat
                    .named(name)
                    .ok_or_else(|| InterpretError {
                        reason: format!("function {} not found", name),
                    })?
                    .clone();
                match found {
                    ContextType::Function(params, stmt) => {
                        // prepare default values
                        for p in params {
                            match self.registrat.named(&p) {
                                None => {
                                    // add default NaslValue::Null for each defined params
                                    self.registrat
                                        .last_mut()
                                        .add_named(&p, ContextType::Value(NaslValue::Null));
                                }
                                Some(_) => {}
                            }
                        }
                        match self.resolve(stmt)? {
                            NaslValue::Return(x) => Ok(*x),
                            a => Ok(a),
                        }
                    }
                    _ => Err(InterpretError {
                        reason: format!("unexpected ContextType: {:?}", found),
                    }),
                }
            }
        };
        self.registrat.drop_last();
        result
    }
}

#[cfg(test)]
mod tests {
    use nasl_syntax::parse;
    use sink::DefaultSink;

    use crate::{
        context::Register, error::InterpretError, loader::NoOpLoader, Interpreter, NaslValue,
    };

    #[test]
    fn default_null_on_user_defined_functions() {
        let code = r###"
        function test(a, b) {
            return a + b;
        }
        test(a: 1, b: 2);
        test(a: 1);
        test();
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser = parse(code).map(|x| match x {
            Ok(x) => interpreter.resolve(x),
            Err(x) => Err(InterpretError {
                reason: x.to_string(),
            }),
        });
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(3))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(1))));
    }
}
