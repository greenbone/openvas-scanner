use std::ops::Range;

use nasl_syntax::{
    NumberBase, Statement, Statement::*, StringCategory, Token, TokenCategory, ACT, Keyword,
};
use sink::Sink;

use crate::{
    context::{ContextType, CtxType, Register},
    error::InterpretError,
    lookup,
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
    oid: Option<&'a str>,
    filename: Option<&'a str>,
    code: &'a str,
    registrat: Register,
    storage: &'a dyn Sink,
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
            NaslValue::Array(_) => true,
            NaslValue::Boolean(boolean) => boolean,
            NaslValue::Null => false,
            NaslValue::Number(number) => number != 0,
            NaslValue::Exit(number) => number != 0,
            NaslValue::AttackCategory(_) => true,
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

    fn resolve_key(&self) -> &str {
        if let Some(oid) = self.oid {
            return oid;
        }
        self.filename.unwrap_or_default()
        
    }

    /// Interpretes a Statement
    pub fn resolve(&mut self, statement: Statement) -> Result<NaslValue, InterpretError> {
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
            Call(function_name, parameters) => {
                let name = &self.code[Range::from(function_name)];
                // get the context
                let mut named = vec![];
                let mut position = vec![];
                match *parameters {
                    Parameter(params) => {
                        for p in params {
                            match p {
                                NamedParameter(token, val) => {
                                    let val = self.resolve(*val)?;
                                    let name = self.code[Range::from(token)].to_owned();
                                    named.push((name, ContextType::Value(val)))
                                }
                                val => {
                                    let val = self.resolve(val)?;
                                    position.push(ContextType::Value(val));
                                }
                            }
                        }
                    }
                    _ => {
                        return Err(InterpretError::new(
                            "invalid statement type for function parameters".to_string(),
                        ))
                    }
                };

                self.registrat
                    .create_root_child(CtxType::Function(named, position));
                // TODO change to use root context to lookup both
                let result = match lookup(name) {
                    // Built-In Function
                    Some(function) => match function(self.resolve_key(), self.storage, &self.registrat) {
                        Ok(value) => Ok(value),
                        Err(x) => Err(InterpretError::new(format!(
                            "unable to call function {}: {:?}",
                            name,
                            x
                        ))),
                    },
                    // Check for user defined function
                    None => todo!(
                        "{} not a built-in function and user function are not yet implemented",
                        name.to_string()
                    ),
                };
                self.registrat.drop_last();
                result
            }
            Declare(_, _) => todo!(),
            Parameter(_) => todo!(),
            Assign(_, _, _, _) => todo!(),
            Operator(_, _) => todo!(),
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
                        return Ok(NaslValue::Exit(rc))
                    }
                }
                // currently blocks don't return something
                Ok(NaslValue::Null)
            }
            NoOp(_) => todo!(),
            EoF => todo!(),
            AttackCategory(cat) => Ok(NaslValue::AttackCategory(cat)),
        }
    }

    pub fn registrat(&self) -> &Register {
        &self.registrat
    }
}
