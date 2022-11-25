use std::ops::Range;

use nasl_syntax::{NumberBase, Statement, Statement::*, StringCategory, Token, TokenCategory};

use crate::{error::InterpetError, lookup, context::{NaslContext, ContextType}};

// TODO Allow multiple value types
/// Persistant storage, which is used to communicate between NASL Scripts
pub trait Storage {
    /// Put a value into the storage
    fn write(&mut self, key: &str, value: &str);
    /// Read a value from the storage
    fn read(&self, key: &str) -> Option<&str>;
}

/// Represents a valid Value of NASL
#[derive(Debug, PartialEq)]
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
}

/// Used to interprete a Statement
pub struct Interpreter<'a> {
    code: &'a str,
    context: &'a mut dyn NaslContext,
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
    /// Transforms a NaslValue into a bool
    fn from(value: NaslValue) -> Self {
        match value {
            NaslValue::String(string) => !string.is_empty() && string != "0",
            NaslValue::Array(_) => true,
            NaslValue::Boolean(boolean) => boolean,
            NaslValue::Null => false,
            NaslValue::Number(number) => number != 0,
        }
    }
}

impl<'a> Interpreter<'a> {
    /// Creates a new Interpreter.
    pub fn new(
        code: &'a str,
        context: &'a mut dyn NaslContext,
        storage: &'a mut dyn Storage,
    ) -> Self {
        Interpreter {
            code,
            context,
            storage,
        }
    }

    /// Interpetes a Statement
    pub fn resolve(&mut self, statement: Statement) -> Result<NaslValue, InterpetError> {
        match statement {
            Array(_, _) => Ok(NaslValue::Null),
            Exit(_) => Ok(NaslValue::Null),
            Return(_) => Ok(NaslValue::Null),
            Include(_) => Ok(NaslValue::Null),
            NamedParameter(_, _) => Ok(NaslValue::Null),
            For(_, _, _, _) => Ok(NaslValue::Null),
            While(_, _) => Ok(NaslValue::Null),
            Repeat(_, _) => Ok(NaslValue::Null),
            ForEach(_, _, _) => Ok(NaslValue::Null),
            FunctionDeclaration(_, _, _) => Ok(NaslValue::Null),
            Primitive(token) => match token.category {
                TokenCategory::String(category) => Ok(NaslValue::String(
                    category.resolve(self.code, Range::from(token)),
                )),
                TokenCategory::Number(base) => Ok(NaslValue::Number(
                    base.resolve(self.code, Range::from(token)),
                )),
                _ => Err(InterpetError {
                    reason: "invalid primitive".to_string(),
                }),
            },
            Variable(_) => Ok(NaslValue::Null),
            Call(function_name, parameters) => {
                // Get the function, if it exists
                let name = &self.code[Range::from(function_name)];
                match lookup(name) {
                    // Built-In Function
                    Some(function) => {
                        let mut function_context = self.context.globals_copy();
                        let params = match *parameters {
                            Parameter(params) => params,
                            _ => {
                                return Err(InterpetError::new(
                                    "invalid statement type for function parameters".to_string(),
                                ))
                            }
                        };
                        for param in params {
                            match param {
                                NamedParameter(parameter_name, parameter_value) => {
                                    // Resolve parameter value
                                    let value_option = self.resolve(*parameter_value);
                                    match value_option {
                                        Ok(value) => function_context.add_named(
                                            &self.code[Range::from(parameter_name)],
                                            ContextType::Value(value),
                                        ),
                                        Err(err) => return Err(err),
                                    }
                                }
                                _ => {
                                    let value_option = self.resolve(param);
                                    match value_option {
                                        Ok(value) => function_context
                                            .add_postitional(ContextType::Value(value)),
                                        Err(err) => return Err(err),
                                    }
                                }
                            };
                        }
                        return match function(function_context.as_mut(), self.storage) {
                            Ok(value) => Ok(value),
                            Err(_) => Err(InterpetError::new(format!(
                                "unable to call function {}",
                                name
                            ))),
                        };
                    }
                    // Check for user defined function
                    None => match self.context.get_named(name) {
                        Some(t) => match t {
                            ContextType::Function(_) => {
                                // Call function
                                todo!();
                            }
                            // Found value is not a function
                            _ => {
                                return Err(InterpetError::new(
                                    format!("{} is not a fucntion", name).to_string(),
                                ))
                            }
                        },
                        // No function Found
                        None => {
                            return Err(InterpetError::new(
                                format!("{} is not defined", name).to_string(),
                            ))
                        }
                    },
                };
            }
            Declare(_, _) => Ok(NaslValue::Null),
            Parameter(_) => Ok(NaslValue::Null),
            Assign(_, _, _, _) => Ok(NaslValue::Null),
            Operator(_, _) => Ok(NaslValue::Null),
            If(condition, if_block, else_block) => match self.resolve(*condition) {
                Ok(value) => {
                    if bool::from(value) {
                        return self.resolve(*if_block);
                    } else if else_block.is_some() {
                        return self.resolve(*else_block.unwrap());
                    }
                    return Ok(NaslValue::Null);
                }
                Err(err) => return Err(err),
            },
            Block(_) => Ok(NaslValue::Null),
            NoOp(_) => Ok(NaslValue::Null),
            EoF => Ok(NaslValue::Null),
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use nasl_syntax::{Statement, StringCategory, TokenCategory};

    use crate::interpreter::NaslValue;

    use super::{ContextType, Interpreter, NaslContext, Storage};

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

    impl<'a> Storage for MockStrorage {
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

    struct MockContext {
        named: HashMap<String, ContextType>,
        positional: Vec<ContextType>,
    }

    impl MockContext {
        fn new() -> Self {
            MockContext {
                named: HashMap::new(),
                positional: vec![],
            }
        }
    }

    impl NaslContext for MockContext {
        fn add_named(&mut self, name: &str, value: ContextType) {
            self.named.insert(name.to_string(), value);
        }
        fn add_postitional(&mut self, value: ContextType) {
            self.positional.push(value);
        }
        fn add_global(&mut self, _: &str, _: ContextType) {}
        fn get_named(&self, name: &str) -> Option<&ContextType> {
            self.named.get(name)
        }
        fn get_positional(&self, pos: usize) -> Option<&ContextType> {
            self.positional.get(pos)
        }
        fn globals_copy(&self) -> Box<dyn NaslContext> {
            Box::new(MockContext::new())
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
        let mut context = MockContext::new();

        let mut interpreter = Interpreter::new(code, &mut context, &mut storage);

        assert_eq!(interpreter.resolve(statement), Ok(NaslValue::Null));
        assert!(storage.map.contains_key("name"));
        assert_eq!(storage.map.get("name").unwrap().as_str(), "test_script");
    }
}

