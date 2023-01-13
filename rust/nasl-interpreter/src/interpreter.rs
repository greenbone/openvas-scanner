use std::collections::HashMap;

use nasl_syntax::{IdentifierType, Statement, Statement::*, Token, TokenCategory, ACT};
use sink::Sink;

use crate::{
    assign::AssignExtension,
    call::CallExtension,
    context::{ContextType, Register},
    declare::DeclareFunctionExtension,
    error::InterpretError,
    include::IncludeExtension,
    loader::Loader,
    operator::OperatorExtension,
};

/// Represents a valid Value of NASL
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NaslValue {
    /// String value
    String(String),
    /// Number value
    Number(i64),
    /// Array value
    Array(Vec<NaslValue>),
    /// Array value
    Dict(HashMap<String, NaslValue>),
    /// Boolean value
    Boolean(bool),
    /// Attack category keyword
    AttackCategory(ACT),
    /// Null value
    Null,
    /// Returns value of the context
    Return(Box<NaslValue>),
    /// Exit value of the script
    Exit(i64),
}

impl ToString for NaslValue {
    fn to_string(&self) -> String {
        match self {
            NaslValue::String(x) => x.to_owned(),
            NaslValue::Number(x) => x.to_string(),
            NaslValue::Array(x) => x
                .iter()
                .enumerate()
                .map(|(i, v)| format!("{}: {}", i, v.to_string()))
                .collect::<Vec<String>>()
                .join(","),
            NaslValue::Dict(x) => x
                .iter()
                .map(|(k, v)| format!("{}: {}", k, v.to_string()))
                .collect::<Vec<String>>()
                .join(","),
            NaslValue::Boolean(x) => x.to_string(),
            NaslValue::Null => "\0".to_owned(),
            NaslValue::Exit(rc) => format!("exit({})", rc),
            NaslValue::AttackCategory(category) => IdentifierType::ACT(*category).to_string(),
            NaslValue::Return(rc) => format!("return({:?})", *rc),
        }
    }
}

/// Used to interpret a Statement
pub struct Interpreter<'a> {
    pub(crate) key: &'a str,
    pub(crate) registrat: &'a mut Register,
    pub(crate) storage: &'a dyn Sink,
    pub(crate) loader: &'a dyn Loader,
}

impl From<NaslValue> for bool {
    fn from(value: NaslValue) -> Self {
        match value {
            NaslValue::String(string) => !string.is_empty() && string != "0",
            NaslValue::Array(v) => !v.is_empty(),
            NaslValue::Boolean(boolean) => boolean,
            NaslValue::Null => false,
            NaslValue::Number(number) => number != 0,
            NaslValue::Exit(number) => number != 0,
            NaslValue::AttackCategory(_) => true,
            NaslValue::Dict(v) => !v.is_empty(),
            NaslValue::Return(_) => true,
        }
    }
}

impl From<&NaslValue> for i64 {
    fn from(value: &NaslValue) -> Self {
        match value {
            NaslValue::String(_) => 1,
            &NaslValue::Number(x) => x,
            NaslValue::Array(_) => 1,
            NaslValue::Dict(_) => 1,
            &NaslValue::Boolean(x) => x as i64,
            &NaslValue::AttackCategory(x) => x as i64,
            NaslValue::Null => 0,
            &NaslValue::Exit(x) => x,
            &NaslValue::Return(_) => -1,
        }
    }
}

impl TryFrom<&Token> for NaslValue {
    type Error = InterpretError;

    fn try_from(token: &Token) -> Result<Self, Self::Error> {
        match token.category() {
            TokenCategory::String(category) => Ok(NaslValue::String(category.clone())),
            TokenCategory::Identifier(IdentifierType::Undefined(id)) => {
                Ok(NaslValue::String(id.clone()))
            }
            TokenCategory::Number(num) => Ok(NaslValue::Number(*num)),
            TokenCategory::Identifier(IdentifierType::Null) => Ok(NaslValue::Null),
            _ => Err(InterpretError {
                reason: format!("invalid primitive {:?}", token.category()),
            }),
        }
    }
}

/// Interpreter always returns a NaslValue or an InterpretError
///
/// When a result does not contain a value than NaslValue::Null must be returned.
pub type InterpretResult = Result<NaslValue, InterpretError>;

impl<'a> Interpreter<'a> {
    /// Creates a new Interpreter.
    pub fn new(
        key: &'a str,
        storage: &'a dyn Sink,
        loader: &'a dyn Loader,
        register: &'a mut Register,
    ) -> Self {
        Interpreter {
            key,
            registrat: register,
            storage,
            loader,
        }
    }

    pub(crate) fn identifier(token: &Token) -> Result<String, InterpretError> {
        match token.category() {
            TokenCategory::Identifier(IdentifierType::Undefined(x)) => Ok(x.clone()),
            cat => Err(InterpretError {
                reason: format!("unexpected category {:?}", cat),
            }),
        }
    }

    /// Interprets a Statement
    pub fn resolve(&mut self, statement: Statement) -> InterpretResult {
        match statement {
            Array(name, position) => {
                let name = &Self::identifier(&name)?;
                let val = self.registrat.named(name).ok_or_else(|| InterpretError {
                    reason: format!("{} not found.", name),
                })?;
                let val = val.clone();

                match (position, val) {
                    (None, ContextType::Value(v)) => Ok(v),
                    (Some(p), ContextType::Value(NaslValue::Array(x))) => {
                        let position = self.resolve(*p)?;
                        let position = i64::from(&position) as usize;
                        let result = x.get(position).ok_or_else(|| InterpretError {
                            reason: format!("positiong {} not found", position),
                        })?;
                        Ok(result.clone())
                    }
                    (Some(p), ContextType::Value(NaslValue::Dict(x))) => {
                        let position = self.resolve(*p)?.to_string();
                        let result = x.get(&position).ok_or_else(|| InterpretError {
                            reason: format!("{} not found.", position),
                        })?;
                        Ok(result.clone())
                    }
                    (p, x) => Err(InterpretError {
                        reason: format!("Internal error statement: {:?} -> {:?}.", p, x),
                    }),
                }
            }
            Exit(stmt) => {
                let rc = self.resolve(*stmt)?;
                match rc {
                    NaslValue::Number(rc) => Ok(NaslValue::Exit(rc)),
                    _ => Err(InterpretError::new("expected numeric value".to_string())),
                }
            }
            Return(stmt) => {
                let rc = self.resolve(*stmt)?;
                Ok(NaslValue::Return(Box::new(rc)))
            }
            Include(inc) => self.include(*inc),
            NamedParameter(_, _) => todo!(),
            For(_, _, _, _) => Ok(NaslValue::Null),
            While(_, _) => todo!(),
            Repeat(_, _) => todo!(),
            ForEach(_, _, _) => todo!(),
            FunctionDeclaration(name, args, exec) => self.declare_function(name, args, exec),
            Primitive(token) => TryFrom::try_from(&token),
            Variable(token) => {
                let name: NaslValue = TryFrom::try_from(&token)?;
                match self.registrat.named(&name.to_string()).ok_or_else(|| {
                    InterpretError::new(format!("variable {} not found", name.to_string()))
                })? {
                    ContextType::Function(_, _) => todo!(),
                    ContextType::Value(result) => Ok(result.clone()),
                }
            }
            Call(name, arguments) => self.call(name, arguments),
            Declare(scope, stmts) => {
                match scope {
                    nasl_syntax::DeclareScope::Global => {
                        for stmt in stmts {
                            if let Variable(ref token) = stmt {
                                if let TokenCategory::Identifier(name) = token.category() {
                                    self.registrat.add_global(
                                        &name.to_string(),
                                        ContextType::Value(NaslValue::Null),
                                    );
                                }
                            };
                        }
                    }
                    nasl_syntax::DeclareScope::Local => {
                        // TODO fix that
                        for stmt in stmts {
                            if let Variable(ref token) = stmt {
                                if let TokenCategory::Identifier(name) = token.category() {
                                    self.registrat.last_mut().add_named(
                                        &name.to_string(),
                                        ContextType::Value(NaslValue::Null),
                                    );
                                }
                            };
                        }
                    }
                }
                Ok(NaslValue::Null)
            }
            // array creation
            Parameter(x) => {
                let mut result = vec![];
                for stmt in x {
                    let val = self.resolve(stmt)?;
                    result.push(val);
                }
                Ok(NaslValue::Array(result))
            }
            Assign(cat, order, left, right) => self.assign(cat, order, *left, *right),
            Operator(sign, stmts) => self.operator(sign, stmts),
            If(condition, if_block, else_block) => match self.resolve(*condition) {
                Ok(value) => {
                    if bool::from(value) {
                        return self.resolve(*if_block);
                    } else if else_block.is_some() {
                        return self.resolve(*else_block.unwrap());
                    }
                    Ok(NaslValue::Null)
                }
                Err(err) => Err(err),
            },
            Block(blocks) => {
                for stmt in blocks {
                    match self.resolve(stmt)? {
                        NaslValue::Exit(rc) => return Ok(NaslValue::Exit(rc)),
                        NaslValue::Return(rc) => return Ok(NaslValue::Return(rc)),
                        _ => {}
                    }
                }
                // currently blocks don't return something
                Ok(NaslValue::Null)
            }
            NoOp(_) => Ok(NaslValue::Null),
            EoF => todo!(),
            AttackCategory(cat) => Ok(NaslValue::AttackCategory(cat)),
        }
    }

    pub fn registrat(&self) -> &Register {
        &self.registrat
    }
}
