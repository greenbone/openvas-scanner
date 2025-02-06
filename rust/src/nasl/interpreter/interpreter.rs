// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::HashMap;

use crate::nasl::interpreter::{
    declare::{DeclareFunctionExtension, DeclareVariableExtension},
    InterpretError,
};
use crate::nasl::syntax::{
    IdentifierType, NaslValue, Statement, StatementKind::*, SyntaxError, Token, TokenCategory,
};

use crate::nasl::utils::{Context, ContextType, Register};

/// Is used to identify the depth of the current statement
///
/// Initial call of retry_resolce sets the first element all others are only
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Position {
    index: Vec<usize>,
}

impl std::fmt::Display for Position {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.index
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<String>>()
                .join(".")
        )
    }
}

impl Position {
    pub fn new(index: usize) -> Self {
        Self { index: vec![index] }
    }

    pub fn up(&mut self) {
        self.index.push(0);
    }

    pub fn reduce_last(&mut self) {
        if let Some(last) = self.index.last_mut() {
            if *last > 0 {
                *last -= 1;
            }
        }
    }

    pub fn down(&mut self) -> Option<usize> {
        let result = self.index.pop();
        if let Some(last) = self.index.last_mut() {
            *last += 1;
        }
        result
    }

    pub fn current_init_statement(&self) -> Self {
        Self {
            index: vec![*self.index.first().unwrap_or(&0)],
        }
    }

    fn root_index(&self) -> usize {
        *self.index.first().unwrap_or(&0)
    }
}

/// Contains data that is specific for a single run
///
/// Some methods start multiple runs (e.g. get_kb_item) and need to have their own specific data to
/// manipulate. To make it more convencient the data that is bound to run is summarized within this
/// struct.
pub(crate) struct RunSpecific {
    pub(crate) register: Register,
    pub(crate) position: Position,
    pub(crate) skip_until_return: Vec<(Position, NaslValue)>,
}

/// Used to interpret a Statement
pub struct Interpreter<'a> {
    pub(crate) run_specific: Vec<RunSpecific>,
    pub(crate) ctxconfigs: &'a Context<'a>,
    pub(crate) index: usize,
}

/// Interpreter always returns a NaslValue or an InterpretError
///
/// When a result does not contain a value than NaslValue::Null must be returned.
pub type InterpretResult = Result<NaslValue, InterpretError>;

impl<'a> Interpreter<'a> {
    /// Creates a new Interpreter
    pub fn new(register: Register, ctxconfigs: &'a Context) -> Self {
        let root_run = RunSpecific {
            register,
            position: Position::new(0),
            skip_until_return: Vec::new(),
        };
        Interpreter {
            run_specific: vec![root_run],
            ctxconfigs,
            index: 0,
        }
    }

    pub(crate) fn identifier(token: &Token) -> Result<String, InterpretError> {
        match token.category() {
            TokenCategory::Identifier(IdentifierType::Undefined(x)) => Ok(x.to_owned()),
            cat => Err(InterpretError::wrong_category(cat)),
        }
    }

    /// May return the next interpreter to run against that statement
    ///
    /// When the interpreter are done a None will be returned. Afterwards it will begin at at 0
    /// again. This is done to inform the caller that all interpreter interpret this statement and
    /// the next Statement can be executed.
    // TODO remove in favor of iterrator of run_specific
    pub fn next_interpreter(&mut self) -> Option<&mut Interpreter<'a>> {
        if self.run_specific.len() == 1 || self.index + 1 == self.run_specific.len() {
            return None;
        }

        // if self.forked_interpreter.is_empty() {
        //     return None;
        // }
        tracing::trace!(amount = self.run_specific.len(), index = self.index,);

        self.index += 1;
        Some(self)
    }

    async fn execute_statements(
        &self,
        key: &str,
        inter: &mut Interpreter<'_>,
        stmt: Result<Statement, SyntaxError>,
    ) -> InterpretResult {
        match stmt {
            Ok(stmt) => inter.resolve(&stmt).await,
            Err(err) => Err(InterpretError::include_syntax_error(key, err)),
        }
    }

    /// Includes a script into to the current runtime by executing it and share the register as
    /// well as DB of the current runtime.
    ///
    // NOTE: This is currently optimized for interpreting runs, but it is very inefficient if we want to
    // switch to a jitc approach or do parallelization of statements within a script. For that it
    // would be necessary to include the statements within a statement list of a script prior of
    // execution. In the current usage (2024-04-02) it would be overkill, but I'm writing a note as
    // I think this can be easily overlooked.
    async fn include(&mut self, name: &Statement) -> InterpretResult {
        match self.resolve(name).await? {
            NaslValue::String(key) => {
                let code = self.ctxconfigs.loader().load(&key)?;

                let mut inter = Interpreter::new(self.register().clone(), self.ctxconfigs);
                for stmt in crate::nasl::syntax::parse(&code) {
                    self.execute_statements(&key, &mut inter, stmt).await?;
                }
                self.set_register(inter.register().clone());
                Ok(NaslValue::Null)
            }
            _ => Err(InterpretError::unsupported(name, "string")),
        }
    }

    /// Changes the internal position and tries to interpret a statement while retrying n times on specific error
    ///
    /// When encountering a retrievable error:
    /// - LoadError(Retry(_))
    /// - StorageError(Retry(_))
    /// - IOError(Interrupted(_))
    ///
    /// then it retries the statement for a given max_attempts times.
    ///
    /// When max_attempts is set to 0 it will it execute it once.
    pub async fn retry_resolve_next(
        &mut self,
        stmt: &Statement,
        max_attempts: usize,
    ) -> InterpretResult {
        self.index = 0;
        self.retry_resolve(stmt, max_attempts).await
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
    pub async fn retry_resolve(
        &mut self,
        stmt: &Statement,
        max_attempts: usize,
    ) -> InterpretResult {
        match self.resolve(stmt).await {
            Ok(x) => Ok(x),
            Err(e) => {
                if max_attempts > 0 {
                    if e.retryable() {
                        Box::pin(self.retry_resolve_next(stmt, max_attempts - 1)).await
                    } else {
                        Err(e)
                    }
                } else {
                    Err(e)
                }
            }
        }
    }

    //// Checks for skip_until_return and returns the value if the current position is in the list
    /// if the root index is smaller than the current position it will return None this is done to
    /// prevent unnecessary statement execution and has to be seen as guardian functionality.
    fn may_return_value(&mut self) -> Option<NaslValue> {
        for (cp, value) in self.skip_until_return().iter() {
            if self.position().root_index() < cp.root_index() {
                return Some(NaslValue::Null);
            }
            if cp == self.position() {
                return Some(value.clone());
            }
        }
        None
    }

    /// Interprets a Statement
    pub(crate) async fn resolve(&mut self, statement: &Statement) -> InterpretResult {
        self.position_mut().up();
        if let Some(val) = self.may_return_value() {
            tracing::trace!(returns=?val, "skipped" );
            self.position_mut().down();
            return Ok(val);
        }
        tracing::trace!("executing");

        let results = {
            match statement.kind() {
                Include(inc) => Box::pin(self.include(inc)).await,
                Array(position) => self.resolve_array(statement, position.clone()).await,
                Exit(stmt) => self.resolve_exit(stmt).await,
                Return(stmt) => self.resolve_return(stmt).await,
                NamedParameter(..) => {
                    unreachable!("named parameter should not be an executable statement.")
                }
                For(assignment, condition, update, body) => {
                    Box::pin(self.for_loop(assignment, condition, update, body)).await
                }
                While(condition, body) => Box::pin(self.while_loop(condition, body)).await,
                Repeat(body, condition) => Box::pin(self.repeat_loop(body, condition)).await,
                ForEach(variable, iterable, body) => {
                    Box::pin(self.for_each_loop(variable, iterable, body)).await
                }
                FunctionDeclaration(name, args, exec) => {
                    self.declare_function(name, args.children(), exec)
                }
                Primitive => self.resolve_primitive(statement),
                Variable => self.resolve_variable(statement),
                Call(arguments) => Box::pin(self.call(statement, arguments.children())).await,
                Declare(stmts) => self.declare_variable(statement.as_token(), stmts),
                Parameter(x) => self.resolve_parameter(x).await,
                Assign(cat, order, left, right) => {
                    Box::pin(self.assign(cat, order, left, right)).await
                }
                Operator(sign, stmts) => Box::pin(self.operator(sign, stmts)).await,
                If(condition, if_block, _, else_block) => {
                    self.resolve_if(condition, if_block, else_block.clone())
                        .await
                }
                Block(blocks) => self.resolve_block(blocks).await,
                NoOp => Ok(NaslValue::Null),
                EoF => Ok(NaslValue::Null),
                AttackCategory => self.resolve_attack_category(statement),
                Continue => Ok(NaslValue::Continue),
                Break => Ok(NaslValue::Break),
            }
            .map_err(|e| {
                if e.origin.is_none() {
                    InterpretError::from_statement(statement, e.kind)
                } else {
                    e
                }
            })
        };
        self.position_mut().down();
        results
    }

    async fn resolve_array(
        &mut self,
        statement: &Statement,
        position: Option<Box<Statement>>,
    ) -> Result<NaslValue, InterpretError> {
        let name = Self::identifier(statement.start())?;
        let val = self
            .register()
            .named(&name)
            .unwrap_or(&ContextType::Value(NaslValue::Null));
        let val = val.clone();

        match (position, val) {
            (None, ContextType::Value(v)) => Ok(v),
            (Some(p), ContextType::Value(NaslValue::Array(x))) => {
                let position = Box::pin(self.resolve(&p)).await?;
                let position = i64::from(&position) as usize;
                let result = x.get(position).unwrap_or(&NaslValue::Null);
                Ok(result.clone())
            }
            (Some(p), ContextType::Value(NaslValue::Dict(x))) => {
                let position = Box::pin(self.resolve(&p)).await?.to_string();
                let result = x.get(&position).unwrap_or(&NaslValue::Null);
                Ok(result.clone())
            }
            (Some(_), ContextType::Value(NaslValue::Null)) => Ok(NaslValue::Null),
            (Some(p), _) => Err(InterpretError::unsupported(&p, "array")),
            (None, ContextType::Function(_, _)) => {
                Err(InterpretError::unsupported(statement, "variable"))
            }
        }
    }

    /// Returns used register
    pub fn register(&self) -> &Register {
        &self.run_specific[self.index].register
    }

    /// Returns used register
    pub(crate) fn register_mut(&mut self) -> &mut Register {
        &mut self.run_specific[self.index].register
    }

    pub(crate) fn position_mut(&mut self) -> &mut Position {
        &mut self.run_specific[self.index].position
    }

    pub(crate) fn position(&self) -> &Position {
        &self.run_specific[self.index].position
    }

    fn set_register(&mut self, val: Register) {
        let rs = &mut self.run_specific[self.index];
        rs.register = val;
    }

    pub(crate) fn skip_until_return(&self) -> &[(Position, NaslValue)] {
        &self.run_specific[self.index].skip_until_return
    }

    async fn resolve_exit(&mut self, statement: &Statement) -> Result<NaslValue, InterpretError> {
        let rc = Box::pin(self.resolve(statement)).await?;
        match rc {
            NaslValue::Number(rc) => Ok(NaslValue::Exit(rc)),
            _ => Err(InterpretError::unsupported(statement, "numeric")),
        }
    }

    async fn resolve_return(&mut self, statement: &Statement) -> Result<NaslValue, InterpretError> {
        let rc = Box::pin(self.resolve(statement)).await?;
        Ok(NaslValue::Return(Box::new(rc)))
    }

    fn resolve_primitive(&self, statement: &Statement) -> Result<NaslValue, InterpretError> {
        TryFrom::try_from(statement.as_token()).map_err(|e: TokenCategory| e.into())
    }

    fn resolve_variable(&mut self, statement: &Statement) -> Result<NaslValue, InterpretError> {
        let name: NaslValue = TryFrom::try_from(statement.as_token())?;
        match self.register().named(&name.to_string()) {
            Some(ContextType::Value(result)) => Ok(result.clone()),
            None => Ok(NaslValue::Null),
            Some(ContextType::Function(_, _)) => {
                Err(InterpretError::unsupported(statement, "variable"))
            }
        }
    }

    async fn resolve_parameter(&mut self, x: &[Statement]) -> Result<NaslValue, InterpretError> {
        let mut result = vec![];
        for stmt in x {
            let val = Box::pin(self.resolve(stmt)).await?;
            result.push(val);
        }
        Ok(NaslValue::Array(result))
    }

    async fn resolve_if(
        &mut self,
        condition: &Statement,
        if_block: &Statement,
        else_block: Option<Box<Statement>>,
    ) -> Result<NaslValue, InterpretError> {
        match Box::pin(self.resolve(condition)).await {
            Ok(value) => {
                if bool::from(value) {
                    return Box::pin(self.resolve(if_block)).await;
                } else if let Some(else_block) = else_block {
                    return Box::pin(self.resolve(else_block.as_ref())).await;
                }
                Ok(NaslValue::Null)
            }
            Err(err) => Err(err),
        }
    }

    async fn resolve_block(&mut self, blocks: &[Statement]) -> Result<NaslValue, InterpretError> {
        self.register_mut().create_child(HashMap::default());
        for stmt in blocks {
            match Box::pin(self.resolve(stmt)).await {
                Ok(x) => {
                    if matches!(
                        x,
                        NaslValue::Exit(_)
                            | NaslValue::Return(_)
                            | NaslValue::Break
                            | NaslValue::Continue
                    ) {
                        self.register_mut().drop_last();
                        return Ok(x);
                    }
                }
                Err(e) => return Err(e),
            }
        }
        self.register_mut().drop_last();
        // currently blocks don't return something
        Ok(NaslValue::Null)
    }

    fn resolve_attack_category(&self, statement: &Statement) -> Result<NaslValue, InterpretError> {
        match statement.as_token().category() {
            TokenCategory::Identifier(IdentifierType::ACT(cat)) => {
                Ok(NaslValue::AttackCategory(*cat))
            }
            _ => unreachable!(
                "AttackCategory must have ACT token but got {:?}, this is an bug within the lexer.",
                statement.as_token()
            ),
        }
    }
}
