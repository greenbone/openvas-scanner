// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::nasl::syntax::{Statement, StatementKind, Token, TokenCategory};

use crate::nasl::interpreter::{error::InterpretError, interpreter::InterpretResult, Interpreter};
use crate::nasl::syntax::NaslValue;
use crate::nasl::utils::ContextType;

/// Is a trait to declare functions
pub(crate) trait DeclareFunctionExtension {
    fn declare_function(
        &mut self,
        name: &Token,
        arguments: &[Statement],
        execution: &Statement,
    ) -> InterpretResult;
}

impl DeclareFunctionExtension for Interpreter<'_> {
    fn declare_function(
        &mut self,
        name: &Token,
        arguments: &[Statement],
        execution: &Statement,
    ) -> InterpretResult {
        let name = &Self::identifier(name)?;
        let mut names = vec![];
        for a in arguments {
            match a.kind() {
                StatementKind::Variable => {
                    let param_name = &Self::identifier(a.as_token())?;
                    names.push(param_name.to_owned());
                }
                _ => return Err(InterpretError::unsupported(a, "variable")),
            }
        }
        self.register_mut()
            .add_global(name, ContextType::Function(names, execution.clone()));
        Ok(NaslValue::Null)
    }
}

pub(crate) trait DeclareVariableExtension {
    fn declare_variable(&mut self, scope: &Token, stmts: &[Statement]) -> InterpretResult;
}

impl DeclareVariableExtension for Interpreter<'_> {
    fn declare_variable(&mut self, scope: &Token, stmts: &[Statement]) -> InterpretResult {
        let mut add = |key: &str| {
            let value = ContextType::Value(NaslValue::Null);
            match scope.category() {
                TokenCategory::Identifier(crate::nasl::syntax::IdentifierType::GlobalVar) => {
                    self.register_mut().add_global(key, value)
                }
                TokenCategory::Identifier(crate::nasl::syntax::IdentifierType::LocalVar) => {
                    self.register_mut().add_local(key, value)
                }
                _ => unreachable!(
                    "{} should not be identified as an declare statement",
                    scope.category()
                ),
            }
        };

        for stmt in stmts {
            if let StatementKind::Variable = stmt.kind() {
                if let TokenCategory::Identifier(name) = stmt.as_token().category() {
                    add(&name.to_string());
                }
            };
        }
        Ok(NaslValue::Null)
    }
}

#[cfg(test)]
mod tests {
    use crate::nasl::test_prelude::*;

    #[test]
    fn declare_local() {
        let mut t = TestBuilder::default();
        t.ok(
            "
        function test(a, b) {
            local_var c;
            c =  a + b;
            return c;
        }",
            NaslValue::Null,
        );
        t.ok("test(a: 1, b: 2);", 3);
        t.ok("c;", NaslValue::Null);
    }

    #[test]
    fn declare_function() {
        let mut t = TestBuilder::default();
        t.ok(
            "function test(a, b) {
            return a + b;
        }",
            NaslValue::Null,
        );
        t.ok("test(a: 1, b: 2);", 3);
    }
}
