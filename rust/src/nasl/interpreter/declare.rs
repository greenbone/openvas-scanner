// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::nasl::{
    ContextType, NaslValue,
    syntax::{
        Statement, Token,
        parser::grammar::{FnDecl, VarScope, VarScopeDecl},
    },
};

use super::interpreter::{Interpreter, Result};

impl Interpreter<'_> {
    pub(crate) fn resolve_fn_decl(&mut self, fn_decl: &FnDecl) -> Result {
        self.register.add_global(
            &fn_decl.fn_name.0,
            ContextType::Function(
                fn_decl
                    .args
                    .items
                    .iter()
                    .map(|ident| ident.0.clone())
                    .collect(),
                fn_decl.block.clone(),
            ),
        );
        Ok(NaslValue::Null)
    }

    pub(crate) fn resolve_var_scope_decl(&mut self, scope_decl: &VarScopeDecl) -> Result {
        for ident in scope_decl.idents.iter() {
            let value = ContextType::Value(NaslValue::Null);
            match scope_decl.scope {
                VarScope::Local => {
                    self.register.add_local(&ident.0, value);
                }
                VarScope::Global => {
                    self.register.add_global(&ident.0, value);
                }
            }
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
    fn declare_global() {
        let mut t = TestBuilder::default();
        t.ok(
            "
        function test(a, b) {
            global_var c;
            c = a + b;
        }",
            NaslValue::Null,
        );
        t.ok("test(a: 1, b: 2);", NaslValue::Null);
        t.ok("c;", 3);
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
