use std::collections::{HashMap, VecDeque};

use crate::nasl::{
    Context, ContextType, Register,
    interpreter::{
        InterpretError,
        declare::{DeclareFunctionExtension, DeclareVariableExtension},
    },
    prelude::NaslValue,
    syntax::{IdentifierType, Lexer, Statement, StatementKind, SyntaxError, Token, TokenCategory},
};

use super::InterpretErrorKind;

#[derive(PartialEq, Eq)]
enum InterpreterState {
    Running,
    Finished,
}

impl InterpreterState {
    fn is_finished(&self) -> bool {
        matches!(self, Self::Finished)
    }
}

/// Represents the result of a function call (`value`) along with
/// the `Token` pointing to the identifier of the function that
/// resulted in this value originally.
#[derive(Clone)]
pub struct FunctionCallData {
    value: NaslValue,
    token: Token,
}

/// This type contains the necessary data to reproduce the execution
/// flow in the case of interpreter forks.
///
/// Its two variants are
///
/// 1. `Collecting`: This variant is used by any interpreter which is
///    currently executing normally.  In this mode, the result of any
///    function call performed by the interpreter within a single
///    top-level statement will be stored along with the `Token` at which
///    the function call took place (as a safeguard). The variant also
///    stores the original `Register` and `Lexer` in order to be able to "rewind"
///    into the exact state before the statement that caused the fork.
/// 2. `Restoring`: This variant is used by all interpreters which were just created due to a fork.
///    In this mode, the interpreter will not perform normal function
///    calls, and will instead return the first value in the `data` field
///    in place of the function call. This is done until the `data` field is
///    exhausted. At that point, execution proceeds normally.
#[derive(Clone)]
pub enum ForkReentryData<'code> {
    Collecting {
        data: Vec<FunctionCallData>,
        register: Register,
        lexer: Lexer<'code>,
    },
    Restoring {
        data: VecDeque<FunctionCallData>,
    },
}

impl<'code> ForkReentryData<'code> {
    fn drain(&mut self) -> VecDeque<FunctionCallData> {
        match self {
            Self::Collecting { data, .. } => data.drain(..).collect(),
            _ => unreachable!(),
        }
    }

    fn register(&self) -> &Register {
        match self {
            Self::Collecting { register, .. } => register,
            _ => unreachable!(),
        }
    }

    fn lexer(&self) -> &Lexer<'code> {
        match self {
            Self::Collecting { lexer, .. } => lexer,
            _ => unreachable!(),
        }
    }

    fn contains_fork(&self) -> bool {
        match self {
            Self::Collecting { data, .. } => data
                .iter()
                .any(|value| matches!(value.value, NaslValue::Fork(_))),
            _ => false,
        }
    }

    /// If in `Collecting` mode, remember the given result. Otherwise
    /// do nothing.
    pub(crate) fn try_collect(&mut self, value: NaslValue, token: &Token) {
        match self {
            ForkReentryData::Collecting { data, .. } => data.push(FunctionCallData {
                value,
                token: token.clone(),
            }),
            ForkReentryData::Restoring { data: _ } => {}
        }
    }

    /// If in `Restoring` mode, remove and return the first stored
    /// result from the queue. Otherwise do nothing.
    pub(crate) fn try_restore(
        &mut self,
        token: &Token,
    ) -> Result<Option<NaslValue>, InterpretError> {
        match self {
            Self::Restoring { data } => {
                if let Some(data) = data.pop_front() {
                    if *token != data.token {
                        return Err(InterpretError::new(InterpretErrorKind::InvalidFork, None));
                    }
                    Ok(Some(data.value))
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }

    fn create_forks(&mut self) -> Vec<Self> {
        let mut data = vec![self.drain()];
        loop {
            let (changed, new_data) = expand_first_fork(data);
            data = new_data;
            if !changed {
                break;
            }
        }
        data.into_iter()
            .map(|data| Self::Restoring { data })
            .collect()
    }

    fn new() -> Self {
        Self::Restoring {
            data: VecDeque::new(),
        }
    }

    fn collecting(register: Register, lexer: Lexer<'code>) -> Self {
        Self::Collecting {
            data: vec![],
            register,
            lexer,
        }
    }

    fn is_empty_or_collecting(&self) -> bool {
        match self {
            ForkReentryData::Collecting { .. } => true,
            ForkReentryData::Restoring { data } => data.is_empty(),
        }
    }
}

/// Expand the first occurrence of `NaslValue::Fork(...)` in the list of collected function
/// calls (i.e. any called function wants to fork), by returning one list per fork value.
///
/// For example (in pseudo-code):
/// expand_first_fork([[1, Fork(2, 3)]]) = [[1, 2], [1, 3]]
/// The boolean return value is true if any expansion took place or false if
/// no expansion took place (that is, if there was no `NaslValue::Fork` in the data).
fn expand_first_fork(
    data: Vec<VecDeque<FunctionCallData>>,
) -> (bool, Vec<VecDeque<FunctionCallData>>) {
    let first_fork = data[0]
        .iter()
        .enumerate()
        .filter_map(|(index, data)| {
            let FunctionCallData { value, token } = data;
            if let NaslValue::Fork(vals) = value {
                Some((index, vals.clone(), token.clone()))
            } else {
                None
            }
        })
        .next();
    if first_fork.is_none() {
        return (false, data);
    }
    let first_fork = first_fork.unwrap();
    let data = data
        .into_iter()
        .flat_map(|d| expand_fork_at(d, first_fork.0, first_fork.1.clone(), first_fork.2.clone()))
        .collect();
    (true, data)
}

fn expand_fork_at(
    data: VecDeque<FunctionCallData>,
    index: usize,
    vals: Vec<NaslValue>,
    token: Token,
) -> Vec<VecDeque<FunctionCallData>> {
    vals.iter()
        .map(|val| {
            let mut data = data.clone();
            data[index] = FunctionCallData {
                value: val.clone(),
                token: token.clone(),
            };
            data
        })
        .collect()
}

pub struct Interpreter<'code, 'ctx> {
    pub(super) register: Register,
    pub(super) context: &'ctx Context<'ctx>,
    pub(super) fork_reentry_data: ForkReentryData<'code>,
    lexer: Lexer<'code>,
    state: InterpreterState,
}

pub type InterpretResult = Result<NaslValue, InterpretError>;

impl<'code, 'ctx> Interpreter<'code, 'ctx> {
    /// Creates a new Interpreter
    pub fn new(register: Register, lexer: Lexer<'code>, context: &'ctx Context) -> Self {
        Interpreter {
            register,
            lexer,
            context,
            fork_reentry_data: ForkReentryData::new(),
            state: InterpreterState::Running,
        }
    }

    pub async fn execute_next_statement(&mut self) -> Option<InterpretResult> {
        self.initialize_fork_data();
        match self.lexer.next() {
            Some(Ok(stmt)) => {
                let result = self.resolve(&stmt).await;
                if matches!(result, Ok(NaslValue::Exit(_))) {
                    self.state = InterpreterState::Finished;
                }
                Some(result)
            }
            Some(Err(err)) => Some(Err(err.into())),
            None => {
                self.state = InterpreterState::Finished;
                None
            }
        }
    }

    pub async fn resolve(&mut self, statement: &Statement) -> InterpretResult {
        use StatementKind::*;
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
            Assign(cat, order, left, right) => Box::pin(self.assign(cat, order, left, right)).await,
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
    }

    async fn resolve_array(
        &mut self,
        statement: &Statement,
        position: Option<Box<Statement>>,
    ) -> Result<NaslValue, InterpretError> {
        let name = statement.start().identifier()?;
        let val = self
            .register
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
        match self.register.named(&name.to_string()) {
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
        self.register.create_child(HashMap::default());
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
                        self.register.drop_last();
                        return Ok(x);
                    }
                }
                Err(e) => return Err(e),
            }
        }
        self.register.drop_last();
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

    async fn include(&mut self, name: &Statement) -> InterpretResult {
        match self.resolve(name).await? {
            NaslValue::String(key) => {
                let code = self.context.loader().load(&key)?;

                let mut inter =
                    Interpreter::new(self.register.clone(), self.lexer.clone(), self.context);
                for stmt in crate::nasl::syntax::parse(&code) {
                    inter.execute_included_statement(&key, stmt).await?;
                }
                self.register = inter.register;
                Ok(NaslValue::Null)
            }
            _ => Err(InterpretError::unsupported(name, "string")),
        }
    }

    async fn execute_included_statement(
        &mut self,
        key: &str,
        stmt: Result<Statement, SyntaxError>,
    ) -> InterpretResult {
        match stmt {
            Ok(stmt) => self.resolve(&stmt).await,
            Err(err) => Err(InterpretError::include_syntax_error(key, err)),
        }
    }

    pub(crate) fn make_forks(mut self) -> Vec<Interpreter<'code, 'ctx>> {
        let forks = self.fork_reentry_data.create_forks();
        let register = self.fork_reentry_data.register();
        let lexer = self.fork_reentry_data.lexer().clone();
        forks
            .into_iter()
            .map(|fork| self.make_fork(fork, register, &lexer))
            .collect()
    }

    fn make_fork(
        &self,
        fork_reentry_data: ForkReentryData<'code>,
        register: &Register,
        lexer: &Lexer<'code>,
    ) -> Interpreter<'code, 'ctx> {
        Self {
            register: register.clone(),
            lexer: lexer.clone(),
            context: self.context,
            fork_reentry_data,
            state: InterpreterState::Running,
        }
    }

    pub(crate) fn wants_to_fork(&self) -> bool {
        self.fork_reentry_data.contains_fork()
    }

    pub(crate) fn initialize_fork_data(&mut self) {
        if self.fork_reentry_data.is_empty_or_collecting() {
            self.fork_reentry_data =
                ForkReentryData::collecting(self.register.clone(), self.lexer.clone());
        }
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.state.is_finished()
    }

    pub fn register(&self) -> &Register {
        &self.register
    }
}
