use std::ops::Range;

use nasl_syntax::{
    Keyword, NumberBase, Statement, Statement::*, StringCategory, Token, TokenCategory, ACT,
};
use sink::Sink;

use crate::{
    assign::AssignExtension,
    call::CallExtension,
    context::{ContextType, Register},
    error::InterpretError, operator::OperatorExtension,
};

/// Represents a valid Value of NASL
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NaslValue {
    /// String value
    String(String),
    /// Number value
    Number(i32),
    /// Array value
    Array(Vec<NaslValue>),
    /// Boolean value
    Boolean(bool),
    /// Attack category keyword
    AttackCategory(ACT),
    /// Null value
    Null,
    /// Exit value of the script
    Exit(i32),
}

impl ToString for NaslValue {
    fn to_string(&self) -> String {
        match self {
            NaslValue::String(x) => x.to_owned(),
            NaslValue::Number(x) => x.to_string(),
            NaslValue::Array(x) => x
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<String>>()
                .join(","),
            NaslValue::Boolean(x) => x.to_string(),
            NaslValue::Null => "\0".to_owned(),
            NaslValue::Exit(rc) => format!("exit({})", rc),
            NaslValue::AttackCategory(category) => Keyword::ACT(*category).to_string(),
        }
    }
}


/// Used to interpret a Statement
pub struct Interpreter<'a> {
    // TODO change to enum
    pub(crate) oid: Option<&'a str>,
    pub(crate) filename: Option<&'a str>,
    pub(crate) code: &'a str,
    pub(crate) registrat: Register,
    pub(crate) storage: &'a dyn Sink,
}

trait PrimitiveResolver<T> {
    fn resolve(&self, code: &str, range: Range<usize>) -> T;
}

impl PrimitiveResolver<String> for StringCategory {
    /// Resolves a range into a String based on code
    fn resolve(&self, code: &str, range: Range<usize>) -> String {
        match self {
            StringCategory::Quotable => code[range].to_owned(),
            StringCategory::Unquotable => {
                let mut string = code[range].to_string();
                string = string.replace(r#"\n"#, "\n");
                string = string.replace(r#"\\"#, "\\");
                string = string.replace(r#"\""#, "\"");
                string = string.replace(r#"\'"#, "'");
                string = string.replace(r#"\r"#, "\r");
                string = string.replace(r#"\t"#, "\t");
                string
            }
        }
    }
}

impl PrimitiveResolver<i32> for NumberBase {
    /// Resolves a range into number based on code
    fn resolve(&self, code: &str, range: Range<usize>) -> i32 {
        i32::from_str_radix(&code[range], self.radix()).unwrap()
    }
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
        }
    }
}


impl From<&NaslValue> for i32 {
    fn from(value: &NaslValue) -> Self {
        match value {
            NaslValue::String(_) => 1,
            &NaslValue::Number(x) => x,
            NaslValue::Array(_) => 1,
            &NaslValue::Boolean(x) => x as i32,
            &NaslValue::AttackCategory(x) => x as i32,
            NaslValue::Null => 0,
            &NaslValue::Exit(x) => x,
        }
    }
}

impl TryFrom<(&str, Token)> for NaslValue {
    type Error = InterpretError;

    fn try_from(value: (&str, Token)) -> Result<Self, Self::Error> {
        let (code, token) = value;
        match token.category {
            TokenCategory::String(category) => Ok(NaslValue::String(
                category.resolve(code, Range::from(token)),
            )),
            TokenCategory::Identifier(None) => Ok(NaslValue::String(
                StringCategory::Unquotable.resolve(code, Range::from(token)),
            )),
            TokenCategory::Number(base) => {
                Ok(NaslValue::Number(base.resolve(code, Range::from(token))))
            }
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
        storage: &'a dyn Sink,
        initial: Vec<(String, ContextType)>,
        oid: Option<&'a str>,
        filename: Option<&'a str>,
        code: &'a str,
    ) -> Self {
        let mut registrat = Register::default();
        registrat.create_root(initial);
        Interpreter {
            oid,
            filename,
            code,
            registrat,
            storage,
        }
    }

    pub(crate) fn resolve_key(&self) -> &str {
        if let Some(oid) = self.oid {
            return oid;
        }
        self.filename.unwrap_or_default()
    }

    /// Interprets a Statement
    pub fn resolve(&mut self, statement: Statement) -> InterpretResult {
        match statement {
            Array(_, _) => todo!(),
            Exit(stmt) => {
                let rc = self.resolve(*stmt)?;
                match rc {
                    NaslValue::Number(rc) => Ok(NaslValue::Exit(rc)),
                    _ => Err(InterpretError::new("expected numeric value".to_string())),
                }
            }
            Return(_) => todo!(),
            Include(_) => todo!(),
            NamedParameter(_, _) => todo!(),
            For(_, _, _, _) => todo!(),
            While(_, _) => todo!(),
            Repeat(_, _) => todo!(),
            ForEach(_, _, _) => todo!(),
            FunctionDeclaration(_, _, _) => todo!(),
            Primitive(token) => TryFrom::try_from((self.code, token)),
            Variable(token) => {
                let name: NaslValue = TryFrom::try_from((self.code, token))?;
                match self.registrat.named(&name.to_string()).ok_or_else(|| {
                    InterpretError::new(format!("variable {} not found", name.to_string()))
                })? {
                    ContextType::Function(_) => todo!(),
                    ContextType::Value(result) => Ok(result.clone()),
                }
            }
            Call(name, arguments) => self.call(name, arguments),
            Declare(_, _) => todo!(),
            // array creation
            Parameter(x) => {
                let mut result = vec![];
                for stmt in x {
                    let val = self.resolve(stmt)?;
                    result.push(val);
                }
                Ok(NaslValue::Array(result))
            },
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
                    if let NaslValue::Exit(rc) = self.resolve(stmt)? {
                        return Ok(NaslValue::Exit(rc));
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
