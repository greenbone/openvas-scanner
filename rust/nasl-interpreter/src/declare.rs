use nasl_syntax::{Statement, Token};

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

#[cfg(test)]
mod tests {
    use nasl_syntax::parse;
    use sink::DefaultSink;

    use crate::{
        context::Register, error::InterpretError, loader::NoOpLoader, Interpreter, NaslValue,
    };

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
