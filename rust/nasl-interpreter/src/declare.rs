use nasl_syntax::{DeclareScope, Statement, Token, TokenCategory};

use crate::{
    error::InterpretError, interpreter::InterpretResult, ContextType, Interpreter, NaslValue,
};

/// Is a trait to declare functions
pub(crate) trait DeclareFunctionExtension {
    fn declare_function(
        &mut self,
        name: Token,
        arguments: Vec<Statement>,
        execution: Box<Statement>,
    ) -> InterpretResult;
}

impl<'a> DeclareFunctionExtension for Interpreter<'a> {
    fn declare_function(
        &mut self,
        name: Token,
        arguments: Vec<Statement>,
        execution: Box<Statement>,
    ) -> InterpretResult {
        let name = &Self::identifier(&name)?;
        let mut names = vec![];
        for a in arguments {
            match a {
                Statement::Variable(token) => {
                    let param_name = &Self::identifier(&token)?;
                    names.push(param_name.to_owned());
                }
                _ => {
                    return Err(InterpretError {
                        reason: "only variable supported".to_owned(),
                    })
                }
            }
        }
        self.registrat
            .add_global(name, ContextType::Function(names, *execution));
        Ok(NaslValue::Null)
    }
}

pub(crate) trait DeclareVariableExtension {
    fn declare_variable(&mut self, scope: DeclareScope, stmts: Vec<Statement>) -> InterpretResult;
}

impl<'a> DeclareVariableExtension for Interpreter<'a> {
    fn declare_variable(&mut self, scope: DeclareScope, stmts: Vec<Statement>) -> InterpretResult {
        let mut add = |key: &str| {
            let value = ContextType::Value(NaslValue::Null);
            match scope {
                DeclareScope::Global => self.registrat.add_global(key, value),
                DeclareScope::Local => self.registrat.add_local(key, value),
            }
        };

        for stmt in stmts {
            if let Statement::Variable(ref token) = stmt {
                if let TokenCategory::Identifier(name) = token.category() {
                    add(&name.to_string());
                }
            };
        }
        Ok(NaslValue::Null)
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
    fn declare_local() {
        let code = r###"
        function test(a, b) {
            local_var c;
            c =  a + b;
            return c;
        }
        test(a: 1, b: 2);
        c;
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
        assert!(matches!(parser.next(), Some(Err(_)))); // not found
    }

    #[test]
    fn declare_function() {
        let code = r###"
        function test(a, b) {
            return a + b;
        }
        test(a: 1, b: 2);
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
    }
}
