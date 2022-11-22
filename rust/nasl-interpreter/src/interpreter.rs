use nasl_syntax::{Statement,Statement::*,TokenCategory, Token, StringCategory, NumberBase};

use crate::{error::{InterpetError}, lookup};


// TODO Allow multiple value types
/// Persistant storage, which is used to communicate between NASL Scripts
pub trait Storage {
    /// Put a value into the storage
    fn write(&mut self, key:&str, value:&str);
    /// Read a value from the storage
    fn read(&self, key:&str) -> Option<&str>;
}

/// Represents a Value within the NaslContext
pub enum ContextType {
    /// Represents a Function definition
    Function(Statement),
    /// Represents a Variable or Parameter
    Value(NaslValue)
}

/// The context represents a temporary storage, which can contain local variables, global variables or defined functions
pub trait NaslContext {
    /// Adds a named value to the Context. This is used for local variables, function parameters and defined functions
    fn add_named(&mut self, name: &str, value: ContextType);
    /// Adds a global variable to the context
    fn add_global(&mut self, name: &str, value: ContextType);
    /// Adds a positional function parameter to the context
    fn add_postitional(&mut self, value: ContextType);
    /// Returns the value of a named parameter/variable or None if it does not exist
    fn get_named(&self, name: &str) -> Option<&ContextType>;
    /// Returns the value of a positional parameter or None if it does not exist
    fn get_positional(&self, pos: usize) -> Option<&ContextType>;
    /// Return a new Context, which contains the global variables of the current Context
    fn globals_copy(&self) -> Box<dyn NaslContext>;
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
    storage: &'a mut dyn Storage
}

impl<'a> Interpreter<'a> {
    /// Creates a new Interpreter.
    pub fn new(code: &'a str, context: &'a mut dyn NaslContext, storage: &'a mut dyn Storage) -> Self {
        Interpreter{code: code, context: context, storage: storage}
    }

    /// Resolves a Token into a String
    fn resolve_string(code: &str, token: Token) -> String {
        match token.category {
            TokenCategory::String(string_category) => match string_category {
            StringCategory::Unquoteable => {
                let mut string = code[token.range()].to_string();
                
                string = string.replace(r#"\n"#, "\n");
                string = string.replace(r#"\\"#, "\\");
                string = string.replace(r#"\""#, "\"");
                string = string.replace(r#"\'"#, "'");
                string = string.replace(r#"\r"#, "\r");
                string = string.replace(r#"\t"#, "\t");

                string
            },
            StringCategory::Quoteable => {
                code[token.range()].to_string()
            }
        },
        _ => "".to_string()
        }
    }

    /// Resolves a Token into a number
    fn resolve_number(code: &str, token: Token) -> i32 {
        match token.category {
            TokenCategory::Number(base) => {
                let base_number: u32;
                match base {
                    NumberBase::Binary => base_number = 2,
                    NumberBase::Octal => base_number = 8,
                    NumberBase::Base10 => base_number = 10,
                    NumberBase::Hex => base_number = 16,
                };
                i32::from_str_radix(&code[token.range()], base_number).unwrap().into()

            }
            _ => 0
        }
    }

    /// Transforms a NaslValue into a bool
    fn to_bool(value: NaslValue) -> bool {
        match value {
            NaslValue::String(string) => string != "" && string != "0",
            NaslValue::Array(_) => true,
            NaslValue::Boolean(boolean) => boolean,
            NaslValue::Null => false,
            NaslValue::Number(number) => number != 0,
        }
    }

    /// Interpetes a Statement
    pub fn resolve(&mut self, statement: Statement) -> Result<NaslValue, InterpetError> {
        match statement {
            Array(_,_ ) => Ok(NaslValue::Null),
            Exit(_) => Ok(NaslValue::Null),
            Return(_) => Ok(NaslValue::Null),
            Include(_) => Ok(NaslValue::Null),
            NamedParameter(_,_ ) => Ok(NaslValue::Null),
            For(_,_ ,_ ,_ ) => Ok(NaslValue::Null),
            While(_,_ ) => Ok(NaslValue::Null),
            Repeat(_,_ ) => Ok(NaslValue::Null),
            ForEach(_,_ ,_ ) => Ok(NaslValue::Null),
            FunctionDeclaration(_,_ ,_ ) => Ok(NaslValue::Null),
            Primitive(token) => {
                match token.category {
                    TokenCategory::String(_) => Ok(NaslValue::String(Self::resolve_string(self.code, token))),
                    TokenCategory::Number(_) => Ok(NaslValue::Number(Self::resolve_number(self.code, token))),
                    _ => Err(InterpetError { reason: "invalid primitive".to_string() })
                }
            },
            Variable(_) => Ok(NaslValue::Null),
            Call(function_name, parameters) => {
                // Get the function, if it exists
                let name = &self.code[function_name.range()];
                match lookup(name){
                    // Built-In Function
                    Some(function) => {
                        let mut function_context = self.context.globals_copy();
                        let params = match *parameters {
                            Parameter(params) => params,
                            _ => return Err(InterpetError::new("invalid statement type for function parameters".to_string())),
                        };
                        for param in params {
                            match param {
                                NamedParameter(parameter_name, parameter_value) => {
                                    // Resolve parameter value
                                    let value_option = self.resolve(*parameter_value);
                                    match value_option {
                                        Ok(value) => function_context.add_named(&self.code[parameter_name.range()], ContextType::Value(value)),
                                        Err(err) => return Err(err),
                                    }
                                },
                                _ => {
                                    let value_option = self.resolve(param);
                                    match value_option {
                                        Ok(value) => function_context.add_postitional(ContextType::Value(value)),
                                        Err(err) => return Err(err),
                                    }
                                },
                            };
                        }
                        match function(function_context.as_mut(), self.storage) {
                            Ok(value) => return Ok(value),
                            Err(_) => return Err(InterpetError::new(format!("unable to call function {}", name).to_string())),
                        };
                    },
                    // Check for user defined function
                    None => match self.context.get_named(name) {
                        Some(t) => match t {
                            ContextType::Function(_) => {
                                // Call function
                                todo!();
                            },
                            // Found value is not a function
                            _ => return Err(InterpetError::new(format!("{} is not a fucntion", name).to_string())),
                        }
                        // No function Found
                        None => return Err(InterpetError::new(format!("{} is not defined", name).to_string())),
                    }
                };               
                
            },
            Declare(_, _) => Ok(NaslValue::Null),
            Parameter(_) => Ok(NaslValue::Null),
            Assign(_, _, _, _) => Ok(NaslValue::Null),
            Operator(_, _)=> Ok(NaslValue::Null),
            If(condition, if_block, else_block) => {
                match self.resolve(*condition) {
                    Ok(value) => {
                        if Self::to_bool(value) {
                            return self.resolve(*if_block);
                        } else if else_block.is_some() {
                            return self.resolve(*else_block.unwrap());
                        }
                        return Ok(NaslValue::Null);
                    },
                    Err(err) => return Err(err),
                }
            },
            Block(_)=> Ok(NaslValue::Null),
            NoOp(_)=> Ok(NaslValue::Null),
            EoF=> Ok(NaslValue::Null),
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use nasl_syntax::{Statement, TokenCategory, StringCategory};

    use crate::interpreter::NaslValue;

    use super::{Storage, ContextType, NaslContext, Interpreter};

    struct MockStrorage {
        map: HashMap<String, String>
    }

    impl MockStrorage {
        fn new() -> Self {
            MockStrorage { map: HashMap::new() }
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
        positional: Vec<ContextType>
    }

    impl MockContext {
        fn new() -> Self {
            MockContext { named: HashMap::new(), positional: vec![] }
        }
    }

    impl NaslContext for MockContext {
        fn add_named(&mut self, name: &str, value: ContextType) {
            self.named.insert(name.to_string(), value);
        }
        fn add_postitional(&mut self, value: ContextType) {
            self.positional.push(value);
        }
        fn add_global(&mut self, _: &str, _: ContextType) {
        }
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
                 position: (0, 11)
                },
            Box::new(
                Statement::Parameter(
                    vec![Statement::Primitive(nasl_syntax::Token {
                        category: nasl_syntax::TokenCategory::String(StringCategory::Unquoteable),
                        position: (13, 24)
                    })]
                )
            )
        );
        let mut storage = MockStrorage::new();
        let mut context = MockContext::new();

        let mut interpreter = Interpreter::new(code, &mut context, &mut storage);

        assert_eq!(interpreter.resolve(statement), Ok(NaslValue::Null));
        assert!(storage.map.contains_key("name"));
        assert_eq!(storage.map.get("name").unwrap().as_str(), "test_script");
    }
}