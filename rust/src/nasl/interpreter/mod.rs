mod error;

mod assign;
mod call;
mod declare;
mod forking_interpreter;
mod include;
mod loop_extension;

#[cfg(test)]
mod tests;

use std::collections::{HashMap, VecDeque};

use crate::nasl::{
    Code, Context, Register,
    error::Span,
    prelude::NaslValue,
    syntax::{
        Ident,
        grammar::{
            Array, ArrayAccess, Ast, Atom, Binary, BinaryOperator, Block, Exit, Expr, If, Include,
            Return, Statement, Unary, UnaryPrefixOperator,
        },
    },
};

use error::IncludeSyntaxError;
pub use error::{FunctionCallError, InterpretError, InterpretErrorKind};
pub use forking_interpreter::ForkingInterpreter;

pub type Result<T = NaslValue, E = InterpretError> = std::result::Result<T, E>;

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
/// the `Span` pointing to the identifier of the function that
/// resulted in this value originally.
#[derive(Clone)]
pub struct FunctionCallData {
    value: NaslValue,
    span: Span,
}

/// This type contains the necessary data to reproduce the execution
/// flow in the case of interpreter forks.
///
/// Its two variants are
///
/// 1. `Collecting`: This variant is used by any interpreter which is
///    currently executing normally.  In this mode, the result of any
///    function call performed by the interpreter within a single
///    top-level statement will be stored along with the `Span` at which
///    the function call took place (as a safeguard). The variant also
///    stores the original `Register` and `Ast` in order to be able to "rewind"
///    into the exact state before the statement that caused the fork.
/// 2. `Restoring`: This variant is used by all interpreters which were just created due to a fork.
///    In this mode, the interpreter will not perform normal function
///    calls, and will instead return the first value in the `data` field
///    in place of the function call. This is done until the `data` field is
///    exhausted. At that point, execution proceeds normally.
#[derive(Clone)]
pub enum ForkReentryData {
    Collecting {
        data: Vec<FunctionCallData>,
        register: Register,
        // TODO: make this a cursor or something similar,
        // since cloning the entire AST seems wasteful.
        ast: Ast,
    },
    Restoring {
        data: VecDeque<FunctionCallData>,
    },
}

impl ForkReentryData {
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

    fn ast(&self) -> &Ast {
        match self {
            Self::Collecting { ast, .. } => ast,
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
    pub(crate) fn try_collect(&mut self, value: NaslValue, span: &Span) {
        match self {
            ForkReentryData::Collecting { data, .. } => data.push(FunctionCallData {
                value,
                span: span.clone(),
            }),
            ForkReentryData::Restoring { data: _ } => {}
        }
    }

    /// If in `Restoring` mode, remove and return the first stored
    /// result from the queue. Otherwise do nothing.
    pub(crate) fn try_restore(&mut self, span: &Span) -> Result<Option<NaslValue>, InterpretError> {
        match self {
            Self::Restoring { data } => {
                if let Some(data) = data.pop_front() {
                    if *span != data.span {
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

    fn collecting(register: Register, ast: Ast) -> Self {
        Self::Collecting {
            data: vec![],
            register,
            ast,
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
            let FunctionCallData { value, span } = data;
            if let NaslValue::Fork(vals) = value {
                Some((index, vals.clone(), span.clone()))
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
    span: Span,
) -> Vec<VecDeque<FunctionCallData>> {
    vals.iter()
        .map(|val| {
            let mut data = data.clone();
            data[index] = FunctionCallData {
                value: val.clone(),
                span: span.clone(),
            };
            data
        })
        .collect()
}

pub struct Interpreter<'ctx> {
    pub(super) register: Register,
    pub(super) context: &'ctx Context<'ctx>,
    pub(super) fork_reentry_data: ForkReentryData,
    ast: Ast,
    state: InterpreterState,
}

impl<'ctx> Interpreter<'ctx> {
    /// Creates a new Interpreter
    pub fn new(register: Register, ast: Ast, context: &'ctx Context) -> Self {
        Interpreter {
            register,
            ast,
            context,
            fork_reentry_data: ForkReentryData::new(),
            state: InterpreterState::Running,
        }
    }

    pub async fn execute_all(&mut self) -> Result<(), InterpretError> {
        while let Some(result) = self.execute_next_statement().await {
            result?;
        }
        Ok(())
    }

    pub async fn execute_next_statement(&mut self) -> Option<Result<NaslValue, InterpretError>> {
        self.initialize_fork_data();
        match self.ast.next_stmt() {
            Some(stmt) => {
                let result = self.resolve(&stmt).await;
                if matches!(result, Ok(NaslValue::Exit(_))) {
                    self.state = InterpreterState::Finished;
                }
                Some(result)
            }
            None => {
                self.state = InterpreterState::Finished;
                None
            }
        }
    }

    pub(super) async fn resolve(
        &mut self,
        statement: &Statement,
    ) -> Result<NaslValue, InterpretError> {
        use Statement::*;
        match statement {
            NoOp => Ok(NaslValue::Null),
            Continue => Ok(NaslValue::Continue),
            Break => Ok(NaslValue::Break),
            ExprStmt(expr) => self.resolve_expr(expr).await,
            Block(block) => self.resolve_block(block).await,
            VarScopeDecl(var_scope_decl) => self.resolve_var_scope_decl(var_scope_decl),
            FnDecl(fn_decl) => self.resolve_fn_decl(fn_decl),
            If(if_) => self.resolve_if(if_).await,
            While(while_) => Box::pin(self.resolve_while(while_)).await,
            Repeat(repeat) => Box::pin(self.resolve_repeat(repeat)).await,
            Foreach(foreach) => Box::pin(self.resolve_foreach(foreach)).await,
            For(for_) => Box::pin(self.resolve_for(for_)).await,
            Exit(exit) => self.resolve_exit(exit).await,
            Include(include_) => self.resolve_include(include_).await,
            Return(return_) => self.resolve_return(return_).await,
        }
        .map_err(|e: InterpretError| {
            if e.origin.is_none() {
                InterpretError::from_statement(statement, e.kind)
            } else {
                e
            }
        })
    }

    pub(super) async fn resolve_expr(&mut self, expr: &Expr) -> Result {
        match expr {
            Expr::Atom(atom) => Box::pin(self.resolve_atom(atom)).await,
            Expr::Binary(binary) => Box::pin(self.resolve_binary(binary)).await,
            Expr::Unary(unary) => Box::pin(self.resolve_unary(unary)).await,
            Expr::Assignment(assignment) => Box::pin(self.resolve_assignment(assignment)).await,
        }
    }

    pub async fn collect_exprs(
        &mut self,
        exprs: impl Iterator<Item = &Expr>,
    ) -> Result<Vec<NaslValue>> {
        let mut vals = vec![];
        for array_access in exprs {
            vals.push(self.resolve_expr(array_access).await?);
        }
        Ok(vals)
    }

    async fn resolve_atom(&mut self, atom: &Atom) -> Result {
        match atom {
            Atom::Literal(literal) => Ok(literal.into()),
            Atom::FnCall(call) => self.resolve_fn_call(call).await,
            Atom::Ident(ident) => Ok(self.resolve_var(ident)?.clone()),
            Atom::Array(array) => self.resolve_array(array).await,
            Atom::ArrayAccess(array_access) => self.resolve_array_access(array_access).await,
            Atom::Increment(increment) => self.resolve_increment(increment).await,
        }
    }

    fn resolve_var(&self, ident: &Ident) -> Result {
        let var = self.register.get(&ident.to_str());
        if let Some(var) = var {
            Ok(self.register.get_val(var).as_value()?.clone())
        } else {
            Ok(NaslValue::Null)
        }
    }

    async fn resolve_array_access(&mut self, array_access: &ArrayAccess) -> Result {
        let lhs = self.resolve_expr(&array_access.lhs_expr).await?;
        let index = self.resolve_expr(&array_access.index_expr).await?;
        lhs.index(index).map(|val| val.clone())
    }

    async fn resolve_unary(&mut self, unary: &Unary) -> Result {
        let rhs = self.resolve_expr(&unary.rhs).await?;
        match unary.op {
            UnaryPrefixOperator::Plus => Ok(rhs),
            UnaryPrefixOperator::Minus => rhs.neg(),
            UnaryPrefixOperator::Bang => rhs.not(),
            UnaryPrefixOperator::Tilde => rhs.bitwise_not(),
        }
    }

    async fn resolve_binary(&mut self, binary: &Binary) -> Result {
        use BinaryOperator::*;
        let lhs = self.resolve_expr(&binary.lhs).await?;
        // Short circuit
        if binary.op == AmpersandAmpersand && !lhs.as_boolean()? {
            return Ok(NaslValue::Boolean(false));
        }
        if binary.op == PipePipe && lhs.as_boolean()? {
            return Ok(NaslValue::Boolean(true));
        }
        let rhs = self.resolve_expr(&binary.rhs).await?;
        match binary.op {
            Plus => Ok(lhs.add(rhs)),
            Minus => Ok(lhs.sub(rhs)),
            Star => lhs.mul(rhs),
            Slash => lhs.div(rhs),
            Percent => lhs.rem(rhs),
            StarStar => lhs.pow(rhs),
            LessLess => lhs.shl(rhs),
            GreaterGreater => lhs.shr(rhs),
            GreaterGreaterGreater => lhs.shr_unsigned(rhs),
            Less => lhs.lt(rhs),
            LessEqual => lhs.le(rhs),
            Greater => lhs.gt(rhs),
            GreaterEqual => lhs.ge(rhs),
            Ampersand => lhs.bitand(rhs),
            Pipe => lhs.bitor(rhs),
            Caret => lhs.bitxor(rhs),
            AmpersandAmpersand => lhs.and(rhs),
            PipePipe => lhs.or(rhs),
            EqualTilde => lhs.match_regex(rhs),
            BangTilde => lhs.match_regex(rhs)?.not(),
            GreaterLess => lhs.match_string(rhs),
            GreaterBangLess => lhs.match_string(rhs)?.not(),
            EqualEqual => Ok(NaslValue::Boolean(lhs == rhs)),
            BangEqual => Ok(NaslValue::Boolean(lhs != rhs)),
        }
    }

    async fn resolve_array(&mut self, array: &Array) -> Result {
        Ok(NaslValue::Array(
            self.collect_exprs(array.items.items.iter()).await?,
        ))
    }

    async fn resolve_exit(&mut self, exit: &Exit) -> Result {
        let rc = Box::pin(self.resolve_expr(&exit.expr)).await?;
        match rc {
            NaslValue::Number(rc) => Ok(NaslValue::Exit(rc)),
            _ => Err(InterpretErrorKind::NonNumericExitCode(rc).into()),
        }
    }

    async fn resolve_return(&mut self, return_: &Return) -> Result {
        let rc = if let Some(ref expr) = return_.expr {
            self.resolve_expr(expr).await?
        } else {
            NaslValue::Null
        };
        Ok(NaslValue::Return(Box::new(rc)))
    }

    async fn resolve_if(
        &mut self,
        If {
            if_branches,
            else_branch,
        }: &If,
    ) -> Result<NaslValue, InterpretError> {
        for (condition, block) in if_branches.iter() {
            let val = self.resolve_expr(condition).await?;
            if bool::from(val) {
                return self.resolve_block(block).await;
            }
        }
        if let Some(block) = else_branch {
            return self.resolve_block(block).await;
        }
        Ok(NaslValue::Null)
    }

    pub(crate) async fn resolve_block(&mut self, block: &Block<Statement>) -> Result {
        self.register.create_child(HashMap::default());
        for stmt in block.items.iter() {
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
        // currently blocks return null
        Ok(NaslValue::Null)
    }

    async fn resolve_include(&mut self, include: &Include) -> Result {
        let loader = self.context.loader();
        let code = Code::load(loader, &include.path)?.parse();
        let file = code.file().clone();
        let ast = code.result().map_err(|errs| {
            InterpretErrorKind::IncludeSyntaxError(IncludeSyntaxError { file, errs })
        })?;
        let mut inter = Interpreter::new(self.register.clone(), ast, self.context);
        Box::pin(inter.execute_all()).await?;
        self.register = inter.register;
        Ok(NaslValue::Null)
    }

    pub(crate) fn make_forks(mut self) -> Vec<Interpreter<'ctx>> {
        let forks = self.fork_reentry_data.create_forks();
        let register = self.fork_reentry_data.register();
        let ast = self.fork_reentry_data.ast().clone();
        forks
            .into_iter()
            .map(|fork| self.make_fork(fork, register, &ast))
            .collect()
    }

    fn make_fork(
        &self,
        fork_reentry_data: ForkReentryData,
        register: &Register,
        ast: &Ast,
    ) -> Interpreter<'ctx> {
        Self {
            register: register.clone(),
            ast: ast.clone(),
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
                ForkReentryData::collecting(self.register.clone(), self.ast.clone());
        }
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.state.is_finished()
    }

    pub fn register(&self) -> &Register {
        &self.register
    }
}
