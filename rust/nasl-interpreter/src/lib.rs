use built_in_functions::description::*;
use context::{NaslContext, Register};
use error::FunctionError;
use interpreter::{NaslValue, Storage};


mod context;
pub mod error;
pub mod interpreter;
pub mod built_in_functions;



pub type NaslFunction = fn(&mut dyn Storage, &mut Register) -> Result<NaslValue, FunctionError>;
pub fn lookup(function_name: &str) -> Option<NaslFunction> {
    match function_name {
        "script_name" => Some(nasl_script_name),
        "script_timeout" => Some(nasl_script_timeout),
        "script_category" => Some(nasl_script_category),
        "script_tag" => Some(nasl_script_tag),
        _ => None,
    }
}
