use std::ops::Range;

use nasl_syntax::{
    NumberBase, Statement, Statement::*, StringCategory, SyntaxError, Token, TokenCategory,
};

use crate::{
    context::{ContextType, CtxType, NaslContext, Register},
    error::InterpetError,
    lookup,
};

// TODO Allow multiple value types
/// Persistant storage, which is used to communicate between NASL Scripts
pub trait Storage {
    /// Put a value into the storage
    fn write(&mut self, key: &str, value: &str);
    /// Read a value from the storage
    fn read(&self, key: &str) -> Option<&str>;
}

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
        }
    }
}

/// Used to interprete a Statement
pub struct Interpreter<'a> {
    code: &'a str,
    registrat: Register,
    storage: &'a mut dyn Storage,
}

trait PrimitiveResolver<T> {
    fn resolve(&self, code: &str, range: Range<usize>) -> T;
}

impl PrimitiveResolver<String> for StringCategory {
    /// Resolves a range into a String based on code
    fn resolve(&self, code: &str, range: Range<usize>) -> String {
        match self {
            StringCategory::Quoteable => code[range].to_owned(),
            StringCategory::Unquoteable => {
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
        }
    }
}

impl TryFrom<(&str, Token)> for NaslValue {
    type Error = InterpetError;

    fn try_from(value: (&str, Token)) -> Result<Self, Self::Error> {
        let (code, token) = value;
        match token.category {
            TokenCategory::String(category) => Ok(NaslValue::String(
                category.resolve(code, Range::from(token)),
            )),
            TokenCategory::Identifier(None) => Ok(NaslValue::String(
                StringCategory::Unquoteable.resolve(code, Range::from(token)),
            )),
            TokenCategory::Number(base) => {
                Ok(NaslValue::Number(base.resolve(code, Range::from(token))))
            }
            _ => Err(InterpetError {
                reason: format!("invalid primitive {:?}", token.category()),
            }),
        }
    }
}

impl<'a> Interpreter<'a> {
    /// Creates a new Interpreter.
    pub fn new(
        storage: &'a mut dyn Storage,
        initial: Vec<(String, ContextType)>,
        code: &'a str,
    ) -> Self {
        let mut registrat = Register::default();
        registrat.create_root(initial);
        Interpreter {
            code,
            registrat,
            storage,
        }
    }

    /// Interpetes a Statement
    pub fn resolve(&mut self, statement: Statement) -> Result<NaslValue, InterpetError> {
        match statement {
            Array(_, _) => todo!(),
            Exit(stmt) => {
                let rc = self.resolve(*stmt)?;
                match rc {
                    NaslValue::Number(rc) => Ok(NaslValue::Exit(rc)),
                    _ => Err(InterpetError::new("expected numeric value".to_string())),
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
                    InterpetError::new(format!("variable {} not found", name.to_string()))
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
                        return Err(InterpetError::new(
                            "invalid statement type for function parameters".to_string(),
                        ))
                    }
                };

                self.registrat
                    .create_root_child(CtxType::Function(named, position));
                // TODO change to use root context to lookup both
                let result = match lookup(name) {
                    // Built-In Function
                    Some(function) => match function(self.storage, &mut self.registrat) {
                        Ok(value) => Ok(value),
                        Err(_) => Err(InterpetError::new(format!(
                            "unable to call function {}",
                            name
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
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use nasl_syntax::{Statement, StringCategory, TokenCategory};

    use crate::interpreter::NaslValue;

    use super::{Interpreter, Storage};

    struct MockStrorage {
        map: HashMap<String, String>,
    }

    impl MockStrorage {
        fn new() -> Self {
            MockStrorage {
                map: HashMap::new(),
            }
        }
    }

    impl Storage for MockStrorage {
        fn write(&mut self, key: &str, value: &str) {
            self.map.insert(key.to_string(), value.to_string());
        }
        fn read(&self, key: &str) -> Option<&str> {
            if self.map.contains_key(key) {
                return Some(self.map[key].as_str());
            }
            None
        }
    }

    #[test]
    fn built_in() {
        let code = "script_name(\"test_script\");";
        let statement = Statement::Call(
            nasl_syntax::Token {
                category: TokenCategory::Identifier(None),
                position: (0, 11),
            },
            Box::new(Statement::Parameter(vec![Statement::Primitive(
                nasl_syntax::Token {
                    category: nasl_syntax::TokenCategory::String(StringCategory::Unquoteable),
                    position: (13, 24),
                },
            )])),
        );
        let mut storage = MockStrorage::new();

        let mut interpreter = Interpreter::new(&mut storage, vec![], code);

        assert_eq!(interpreter.resolve(statement), Ok(NaslValue::Null));
        assert!(storage.map.contains_key("name"));
        assert_eq!(storage.map.get("name").unwrap().as_str(), "test_script");
    }
}
