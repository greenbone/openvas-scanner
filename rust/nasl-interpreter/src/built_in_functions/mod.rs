use crate::{Register, NaslValue, ContextType, lookup_keys::FC_ANON_ARGS};

pub mod description;
pub mod hostname;
pub mod rand;
pub mod string;
pub mod array;
pub mod function;

pub(crate) fn resolve_positional_arguments(register: &Register) -> Vec<NaslValue> {
    match register.named(FC_ANON_ARGS).cloned() {
        Some(ContextType::Value(NaslValue::Array(arr))) => arr,
        _ => vec![],
    }
}


