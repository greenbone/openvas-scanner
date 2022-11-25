use built_in_functions::{description::*, NaslFunction};


mod context;
pub mod error;
pub mod interpreter;
pub mod built_in_functions;


pub fn lookup(function_name: &str) -> Option<NaslFunction> {
    match function_name {
        "script_name" => Some(nasl_script_name),
        "script_timeout" => Some(nasl_script_timeout),
        "script_category" => Some(nasl_script_category),
        "script_tag" => Some(nasl_script_tag),
        _ => None,
    }
}
