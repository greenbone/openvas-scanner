// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use nasl_syntax::{Statement, Token, TokenCategory};

use crate::{error::InterpretError, interpreter::InterpretResult, Interpreter};
use nasl_builtin_utils::ContextType;
use nasl_syntax::NaslValue;

/// Is a trait to declare functions
pub(crate) trait DeclareFunctionExtension {
    fn declare_function(
        &mut self,
        name: &Token,
        arguments: &[Statement],
        execution: &Statement,
    ) -> InterpretResult;
}

impl<'a, K> DeclareFunctionExtension for Interpreter<'a, K>
where
    K: AsRef<str>,
{
    fn declare_function(
        &mut self,
        name: &Token,
        arguments: &[Statement],
        execution: &Statement,
    ) -> InterpretResult {
        let name = &Self::identifier(name)?;
        let mut names = vec![];
        for a in arguments {
            match a {
                Statement::Variable(token) => {
                    let param_name = &Self::identifier(token)?;
                    names.push(param_name.to_owned());
                }
                _ => return Err(InterpretError::unsupported(a, "variable")),
            }
        }
        self.registrat
            .add_global(name, ContextType::Function(names, execution.clone()));
        Ok(NaslValue::Null)
    }
}

pub(crate) trait DeclareVariableExtension {
    fn declare_variable(&mut self, scope: &Token, stmts: &[Statement]) -> InterpretResult;
}

impl<'a, K> DeclareVariableExtension for Interpreter<'a, K> {
    fn declare_variable(&mut self, scope: &Token, stmts: &[Statement]) -> InterpretResult {
        let mut add = |key: &str| {
            let value = ContextType::Value(NaslValue::Null);
            match scope.category() {
                TokenCategory::Identifier(nasl_syntax::IdentifierType::GlobalVar) => {
                    self.registrat.add_global(key, value)
                }
                TokenCategory::Identifier(nasl_syntax::IdentifierType::LocalVar) => {
                    self.registrat.add_local(key, value)
                }
                _ => unreachable!(
                    "{} should not be identified as an declare statement",
                    scope.category()
                ),
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
    use crate::*;

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
        let mut register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("unexpected parse error")));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
        assert_eq!(parser.next(), Some(Ok(3.into())));
        assert!(matches!(parser.next(), Some(Ok(NaslValue::Null)))); // not found
    }

    #[test]
    fn declare_function() {
        let code = r###"
        function test(a, b) {
            return a + b;
        }
        test(a: 1, b: 2);
        "###;
        let mut register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("unexpected parse error")));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
        assert_eq!(parser.next(), Some(Ok(3.into())));
    }
}
