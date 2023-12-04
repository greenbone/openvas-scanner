// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{collections::HashMap, io};

use nasl_syntax::{
    IdentifierType, LoadError, NaslValue, Statement, Statement::*, Token, TokenCategory,
};
use storage::StorageError;

use crate::{
    assign::AssignExtension,
    call::CallExtension,
    declare::{DeclareFunctionExtension, DeclareVariableExtension},
    include::IncludeExtension,
    loop_extension::LoopExtension,
    operator::OperatorExtension,
    InterpretError, InterpretErrorKind,
};

use nasl_builtin_utils::{Context, ContextType, Register};

/// Used to interpret a Statement
pub struct Interpreter<'a, K> {
    pub(crate) registrat: &'a mut Register,
    pub(crate) ctxconfigs: &'a Context<'a, K>,
}

/// Interpreter always returns a NaslValue or an InterpretError
///
/// When a result does not contain a value than NaslValue::Null must be returned.
pub type InterpretResult = Result<NaslValue, InterpretError>;

impl<'a, K> Interpreter<'a, K>
where
    K: AsRef<str>,
{
    /// Creates a new Interpreter.
    pub fn new(register: &'a mut Register, ctxconfigs: &'a Context<K>) -> Self {
        Interpreter {
            registrat: register,
            ctxconfigs,
        }
    }

    pub(crate) fn identifier(token: &Token) -> Result<String, InterpretError> {
        match token.category() {
            TokenCategory::Identifier(IdentifierType::Undefined(x)) => Ok(x.to_owned()),
            cat => Err(InterpretError::wrong_category(cat)),
        }
    }

    /// Tries to interpret a statement and retries n times on a retry error
    ///
    /// When encountering a retrievable error:
    /// - LoadError(Retry(_))
    /// - StorageError(Retry(_))
    /// - IOError(Interrupted(_))
    ///
    /// then it retries the statement for a given max_attempts times.
    ///
    /// When max_attempts is set to 0 it will it execute it once.
    pub fn retry_resolve(&mut self, stmt: &Statement, max_attempts: usize) -> InterpretResult {
        match self.resolve(stmt) {
            Ok(x) => Ok(x),
            Err(e) => {
                if max_attempts > 0 {
                    match e.kind {
                        InterpretErrorKind::LoadError(LoadError::Retry(_))
                        | InterpretErrorKind::IOError(io::ErrorKind::Interrupted)
                        | InterpretErrorKind::StorageError(StorageError::Retry(_)) => {
                            self.retry_resolve(stmt, max_attempts - 1)
                        }
                        _ => Err(e),
                    }
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Interprets a Statement
    pub fn resolve(&mut self, statement: &Statement) -> InterpretResult {
        match statement {
            Array(name, position, _) => {
                let name = Self::identifier(name)?;
                let val = self
                    .registrat
                    .named(&name)
                    .unwrap_or(&ContextType::Value(NaslValue::Null));
                let val = val.clone();

                match (position, val) {
                    (None, ContextType::Value(v)) => Ok(v),
                    (Some(p), ContextType::Value(NaslValue::Array(x))) => {
                        let position = self.resolve(p)?;
                        let position = i64::from(&position) as usize;
                        let result = x.get(position).unwrap_or(&NaslValue::Null);
                        Ok(result.clone())
                    }
                    (Some(p), ContextType::Value(NaslValue::Dict(x))) => {
                        let position = self.resolve(p)?.to_string();
                        let result = x.get(&position).unwrap_or(&NaslValue::Null);
                        Ok(result.clone())
                    }
                    (Some(_), ContextType::Value(NaslValue::Null)) => Ok(NaslValue::Null),
                    (Some(p), _) => Err(InterpretError::unsupported(p, "array")),
                    (None, ContextType::Function(_, _)) => {
                        Err(InterpretError::unsupported(statement, "variable"))
                    }
                }
            }
            Exit(_, stmt, _) => {
                let rc = self.resolve(stmt)?;
                match rc {
                    NaslValue::Number(rc) => Ok(NaslValue::Exit(rc)),
                    _ => Err(InterpretError::unsupported(stmt, "numeric")),
                }
            }
            Return(_, stmt) => {
                let rc = self.resolve(stmt)?;
                Ok(NaslValue::Return(Box::new(rc)))
            }
            Include(_, inc, _) => self.include(inc),
            NamedParameter(..) => {
                unreachable!("named parameter should not be an executable statement.")
            }
            For(_, assignment, condition, update, body) => {
                self.for_loop(assignment, condition, update, body)
            }
            While(_, condition, body) => self.while_loop(condition, body),
            Repeat(_, body, condition) => self.repeat_loop(body, condition),
            ForEach(_, variable, iterable, body) => self.for_each_loop(variable, iterable, body),
            FunctionDeclaration(_, name, args, _, exec) => self.declare_function(name, args, exec),
            Primitive(token) => TryFrom::try_from(token).map_err(|e: TokenCategory| e.into()),
            Variable(token) => {
                let name: NaslValue = TryFrom::try_from(token)?;
                match self.registrat.named(&name.to_string()) {
                    Some(ContextType::Value(result)) => Ok(result.clone()),
                    None => Ok(NaslValue::Null),
                    Some(ContextType::Function(_, _)) => {
                        Err(InterpretError::unsupported(statement, "variable"))
                    }
                }
            }
            Call(name, arguments, _) => self.call(name, arguments),
            Declare(scope, stmts) => self.declare_variable(scope, stmts),
            // array creation
            Parameter(x) => {
                let mut result = vec![];
                for stmt in x {
                    let val = self.resolve(stmt)?;
                    result.push(val);
                }
                Ok(NaslValue::Array(result))
            }
            Assign(cat, order, left, right) => self.assign(cat, order, left, right),
            Operator(sign, stmts) => self.operator(sign, stmts),
            If(_, condition, if_block, _, else_block) => match self.resolve(condition) {
                Ok(value) => {
                    if bool::from(value) {
                        return self.resolve(if_block);
                    } else if let Some(else_block) = else_block {
                        return self.resolve(else_block.as_ref());
                    }
                    Ok(NaslValue::Null)
                }
                Err(err) => Err(err),
            },
            Block(_, blocks, _) => {
                self.registrat.create_child(HashMap::default());
                for stmt in blocks {
                    match self.resolve(stmt) {
                        Ok(x) => {
                            if matches!(
                                x,
                                NaslValue::Exit(_)
                                    | NaslValue::Return(_)
                                    | NaslValue::Break
                                    | NaslValue::Continue
                            ) {
                                self.registrat.drop_last();
                                return Ok(x);
                            }
                        }
                        Err(e) => return Err(e),
                    }
                }
                self.registrat.drop_last();
                // currently blocks don't return something
                Ok(NaslValue::Null)
            }
            NoOp(_) => Ok(NaslValue::Null),
            EoF => Ok(NaslValue::Null),
            AttackCategory(t) => { 
                match t.category() {
                    TokenCategory::Identifier(IdentifierType::ACT(cat)) => Ok(NaslValue::AttackCategory(*cat)),
                    _ => unreachable!("AttackCategory must have ACT token but got {t:?}, this is an bug within the lexer.")

                }

                
            },
            Continue(_) => Ok(NaslValue::Continue),
            Break(_) => Ok(NaslValue::Break),
        }
        .map_err(|e| {
            if e.origin.is_none() {
                InterpretError::from_statement(statement, e.kind)
            } else {
                e
            }
        })
    }

    pub(crate) fn registrat(&self) -> &Register {
        self.registrat
    }
}
