use crate::{error::FunctionError, interpreter::{Storage, ContextType, NaslContext, NaslValue}};



pub fn nasl_script_name( ctx: & dyn NaslContext, storage: &mut dyn Storage) -> Result<NaslValue, FunctionError> {
    match ctx.get_positional(0) {
        None => return Err(FunctionError::new("expected at least one possitional argument, 0 were given.".to_string())),
        Some(ct) => match ct {
            ContextType::Value(value_type) => match value_type {
                NaslValue::String(value) => {
                    storage.write("name", value.as_str());
                    Ok(NaslValue::Null)
                },
                _ => return Err(FunctionError::new("argument is of the wrong type, string was expected".to_string())),
            },
            _ => return Err(FunctionError::new("argument is a function, string was expected".to_string())),
        }
    }
}

pub fn nasl_script_timeout( ctx: & dyn NaslContext, storage: &mut dyn Storage) -> Result<NaslValue, FunctionError>{
    match ctx.get_positional(0) {
        None => return Err(FunctionError::new("expected at least one possitional argument, 0 were given.".to_string())),
        Some(ct) => match ct {
            ContextType::Value(value_type) => match value_type {
                NaslValue::String(value) => {
                    storage.write("timeout", value.as_str());
                    Ok(NaslValue::Null)
                },
                _ => return Err(FunctionError::new("argument is of the wrong type, string was expected".to_string())),
            },
            _ => return Err(FunctionError::new("argument is a function, string was expected".to_string())),
        }
    }
}

pub fn nasl_script_category( ctx: & dyn NaslContext , storage: &mut dyn Storage) -> Result<NaslValue, FunctionError> {
    match ctx.get_positional(0) {
        None => return Err(FunctionError::new("expected at least one possitional argument, 0 were given.".to_string())),
        Some(ct) => match ct {
            ContextType::Value(value_type) => match value_type {
                NaslValue::Number(value) => {
                    storage.write("name", value.to_string().as_str());
                    Ok(NaslValue::Null)
                },
                _ => return Err(FunctionError::new("argument is of the wrong type, number was expected".to_string())),
            },
            _ => return Err(FunctionError::new("argument is a function, number was expected".to_string())),
        }
    }
}

pub fn nasl_script_tag( ctx: & dyn NaslContext, storage: &mut dyn Storage) -> Result<NaslValue, FunctionError> {
    let key = match ctx.get_named("name") {
        None => return Err(FunctionError::new("expected at least one possitional argument, 0 were given.".to_string())),
        Some(ct) => match ct {
            ContextType::Value(value_type) => match value_type {
                NaslValue::String(value) => value,
                _ => return Err(FunctionError::new("argument is of the wrong type, string was expected".to_string()))
            },
            _ => return Err(FunctionError::new("argument is a function, string was expected".to_string())),
        }
    };

    let value = match ctx.get_named("value") {
        None => return Err(FunctionError::new("expected at least one possitional argument, 0 were given.".to_string())),
        Some(ct) => match ct {
            ContextType::Value(value_type) => match value_type {
                NaslValue::String(value) => value,
                _ => return Err(FunctionError::new("argument is of the wrong type, string was expected".to_string()))
            },
            _ => return Err(FunctionError::new("argument is a function, string was expected".to_string())),
        }
    };


    storage.write(key.as_str(), value.as_str());
    Ok(NaslValue::Null)
}

