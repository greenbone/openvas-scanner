use std::collections::HashMap;

use nasl_syntax::{IdentifierType, Statement, Statement::*, Token, TokenCategory, ACT};
use sink::Sink;

use crate::{
    assign::AssignExtension,
    call::CallExtension,
    context::{ContextType, Register},
    declare::{DeclareFunctionExtension, DeclareVariableExtension},
    error::InterpretError,
    include::IncludeExtension,
    loader::Loader,
    loop_extension::LoopExtension,
    operator::OperatorExtension,
};

/// Represents a valid Value of NASL
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NaslValue {
    /// String value
    String(String),
    /// Data value
    Data(Vec<u8>),
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
    /// Signals continuing a loop
    Continue,
    /// Signals a break of a control structure
    Break,
    /// Exit value of the script
    Exit(i64),
}

impl From<Vec<u8>> for NaslValue {
    fn from(s: Vec<u8>) -> Self {
        Self::Data(s)
    }
}

impl From<bool> for NaslValue {
    fn from(b: bool) -> Self {
        NaslValue::Boolean(b)
    }
}

impl From<&str> for NaslValue {
    fn from(s: &str) -> Self {
        Self::String(s.to_owned())
    }
}

impl From<String> for NaslValue {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<i64> for NaslValue {
    fn from(n: i64) -> Self {
        Self::Number(n)
    }
}

impl From<usize> for NaslValue {
    fn from(n: usize) -> Self {
        Self::Number(n as i64)
    }
}

impl From<HashMap<String, NaslValue>> for NaslValue {
    fn from(x: HashMap<String, NaslValue>) -> Self {
        NaslValue::Dict(x)
    }
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
            NaslValue::Data(x) => x.iter().map(|x| *x as char).collect(),
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
            NaslValue::Continue => "".to_string(),
            NaslValue::Break => "".to_string(),
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
            NaslValue::Data(v) => !v.is_empty(),
            NaslValue::Boolean(boolean) => boolean,
            NaslValue::Null => false,
            NaslValue::Number(number) => number != 0,
            NaslValue::Exit(number) => number != 0,
            NaslValue::AttackCategory(_) => true,
            NaslValue::Dict(v) => !v.is_empty(),
            NaslValue::Return(_) => true,
            NaslValue::Continue => false,
            NaslValue::Break => false,
        }
    }
}

impl From<&NaslValue> for i64 {
    fn from(value: &NaslValue) -> Self {
        match value {
            NaslValue::String(_) => 1,
            &NaslValue::Number(x) => x,
            NaslValue::Array(_) => 1,
            NaslValue::Data(_) => 1,
            NaslValue::Dict(_) => 1,
            &NaslValue::Boolean(x) => x as i64,
            &NaslValue::AttackCategory(x) => x as i64,
            NaslValue::Null => 0,
            &NaslValue::Exit(x) => x,
            &NaslValue::Return(_) => -1,
            &NaslValue::Continue => 0,
            &NaslValue::Break => 0,
        }
    }
}

impl From<NaslValue> for i64 {
    fn from(nv: NaslValue) -> Self {
        i64::from(&nv)
    }
}

impl TryFrom<&Token> for NaslValue {
    type Error = InterpretError;

    fn try_from(token: &Token) -> Result<Self, Self::Error> {
        match token.category() {
            TokenCategory::String(category) | TokenCategory::IPv4Address(category) => {
                Ok(NaslValue::String(category.clone()))
            }
            TokenCategory::Identifier(IdentifierType::Undefined(id)) => {
                Ok(NaslValue::String(id.clone()))
            }
            TokenCategory::Number(num) => Ok(NaslValue::Number(*num)),
            TokenCategory::Identifier(IdentifierType::Null) => Ok(NaslValue::Null),
            TokenCategory::Identifier(IdentifierType::True) => Ok(NaslValue::Boolean(true)),
            TokenCategory::Identifier(IdentifierType::False) => Ok(NaslValue::Boolean(false)),
            _ => Err(InterpretError::new(format!(
                "{} is not a primitive.",
                token.category()
            ))),
        }
    }
}

impl From<NaslValue> for Vec<NaslValue> {
    fn from(value: NaslValue) -> Self {
        match value {
            NaslValue::Array(ret) => ret,
            NaslValue::Dict(ret) => ret.values().cloned().collect(),
            NaslValue::Boolean(_) => vec![value],
            NaslValue::Number(_) => vec![value],
            NaslValue::String(ret) => ret
                .chars()
                .map(|x| NaslValue::String(x.to_string()))
                .collect(),
            _ => vec![],
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
            _ => Err(InterpretError::new(format!(
                "{} is not a primitive.",
                token.category()
            ))),
        }
    }

    /// Interprets a Statement
    pub fn resolve(&mut self, statement: &Statement) -> InterpretResult {
        match statement {
            Array(name, position) => {
                let name = &Self::identifier(name)?;
                let val = self
                    .registrat
                    .named(name)
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
                    (_, _) => Err(InterpretError::new(format!("{} is not resolvable.", name))),
                }
            }
            Exit(stmt) => {
                let rc = self.resolve(stmt)?;
                match rc {
                    NaslValue::Number(rc) => Ok(NaslValue::Exit(rc)),
                    _ => Err(InterpretError::new("expected numeric value".to_string())),
                }
            }
            Return(stmt) => {
                let rc = self.resolve(stmt)?;
                Ok(NaslValue::Return(Box::new(rc)))
            }
            Include(inc) => self.include(inc),
            NamedParameter(_, _) => todo!(),
            For(assignment, condition, update, body) => {
                self.for_loop(assignment, condition, update, body)
            }
            While(condition, body) => self.while_loop(condition, body),
            Repeat(body, condition) => self.repeat_loop(body, condition),
            ForEach(variable, iterable, body) => self.for_each_loop(variable, iterable, body),
            FunctionDeclaration(name, args, exec) => self.declare_function(name, args, exec),
            Primitive(token) => TryFrom::try_from(token),
            Variable(token) => {
                let name: NaslValue = TryFrom::try_from(token)?;
                match self.registrat.named(&name.to_string()).ok_or_else(|| {
                    InterpretError::new(format!("variable {} not found", name.to_string()))
                })? {
                    ContextType::Function(_, _) => todo!(),
                    ContextType::Value(result) => Ok(result.clone()),
                }
            }
            Call(name, arguments) => self.call(name, arguments),
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
            If(condition, if_block, else_block) => match self.resolve(condition) {
                Ok(value) => {
                    if bool::from(value) {
                        return self.resolve(if_block);
                    } else if else_block.is_some() {
                        return self.resolve(else_block.as_ref().unwrap());
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
                        NaslValue::Break => return Ok(NaslValue::Break),
                        NaslValue::Continue => return Ok(NaslValue::Continue),
                        _ => {}
                    }
                }
                // currently blocks don't return something
                Ok(NaslValue::Null)
            }
            NoOp(_) => Ok(NaslValue::Null),
            EoF => todo!(),
            AttackCategory(cat) => Ok(NaslValue::AttackCategory(*cat)),
            Continue => Ok(NaslValue::Continue),
            Break => Ok(NaslValue::Break),
        }
        .map_err(|e| {
            if e.col == 0 && e.line == 0 {
                InterpretError::from_statement(statement, e.reason)
            } else {
                e
            }
        })
    }

    pub(crate) fn registrat(&self) -> &Register {
        self.registrat
    }
}
