use std::collections::{HashMap, VecDeque};

use crate::nasl::{
    interpreter::declare::{DeclareFunctionExtension, DeclareVariableExtension},
    interpreter::InterpretError,
    prelude::NaslValue,
    syntax::{IdentifierType, Lexer, Statement, StatementKind, SyntaxError, TokenCategory},
    Context, ContextType, Register,
};

use super::forking_interpreter::InterpreterState;

#[derive(Clone)]
pub enum ForkReentryData<'code> {
    Collecting {
        data: Vec<NaslValue>,
        register: Register,
        lexer: Lexer<'code>,
    },
    Restoring(VecDeque<NaslValue>),
}

impl<'code> ForkReentryData<'code> {
    fn drain(&mut self) -> VecDeque<NaslValue> {
        match self {
            Self::Collecting { data, .. } => data.drain(..).collect(),
            _ => unreachable!(),
        }
    }

    fn contains_fork(&self) -> bool {
        match self {
            Self::Collecting { data, .. } => {
                data.iter().any(|val| matches!(val, NaslValue::Fork(_)))
            }
            _ => false,
        }
    }

    pub(crate) fn try_push(&mut self, result: NaslValue) {
        match self {
            ForkReentryData::Collecting { data, .. } => data.push(result),
            ForkReentryData::Restoring(_) => {}
        }
    }

    pub(crate) fn try_pop(&mut self) -> Option<NaslValue> {
        match self {
            Self::Restoring(data) => data.pop_front(),
            _ => None,
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

    fn create_forks(&mut self) -> Vec<Self> {
        let mut data = vec![self.drain()];
        loop {
            let (changed, new_data) = expand_first_fork(data);
            data = new_data;
            if !changed {
                break;
            }
        }
        data.into_iter().map(|data| Self::Restoring(data)).collect()
    }

    fn new() -> Self {
        Self::Restoring(VecDeque::new())
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
            ForkReentryData::Restoring(data) => data.is_empty(),
        }
    }
}

fn expand_first_fork(data: Vec<VecDeque<NaslValue>>) -> (bool, Vec<VecDeque<NaslValue>>) {
    let first_fork = data[0]
        .iter()
        .enumerate()
        .filter_map(|(index, val)| {
            if let NaslValue::Fork(vals) = val {
                Some((index, vals.clone()))
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
        .flat_map(|d| expand_fork_at(d, first_fork.0, first_fork.1.clone()))
        .collect();
    (true, data)
}

fn expand_fork_at(
    data: VecDeque<NaslValue>,
    index: usize,
    vals: Vec<NaslValue>,
) -> Vec<VecDeque<NaslValue>> {
    vals.iter()
        .map(|val| {
            let mut data = data.clone();
            data[index] = val.clone();
            data
        })
        .collect()
}

pub struct Interpreter<'code, 'ctx> {
    pub register: Register,
    lexer: Lexer<'code>,
    pub context: &'ctx Context<'ctx>,
    pub fork_reentry_data: ForkReentryData<'code>,
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
        }
    }

    pub async fn execute_next_statement(&mut self) -> Option<InterpretResult> {
        self.initialize_fork_data();
        match self.lexer.next() {
            Some(Ok(stmt)) => Some(self.resolve(&stmt).await),
            Some(Err(err)) => Some(Err(err.into())),
            None => None,
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

    pub(crate) fn create_forks(mut self) -> Vec<(InterpreterState, Interpreter<'code, 'ctx>)> {
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
    ) -> (InterpreterState, Interpreter<'code, 'ctx>) {
        let interpreter = Self {
            register: register.clone(),
            lexer: lexer.clone(),
            context: self.context,
            fork_reentry_data,
        };
        (InterpreterState::Running, interpreter)
    }

    pub(crate) fn should_fork(&self) -> bool {
        self.fork_reentry_data.contains_fork()
    }

    pub(crate) fn initialize_fork_data(&mut self) {
        if self.fork_reentry_data.is_empty_or_collecting() {
            self.fork_reentry_data =
                ForkReentryData::collecting(self.register.clone(), self.lexer.clone());
        }
    }
}
