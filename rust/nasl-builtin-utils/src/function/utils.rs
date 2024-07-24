//! Convenience functions, used internally in the `NaslFunctionArg` macro.

use crate::function::FromNaslValue;
use crate::{ContextType, FunctionErrorKind, Register};
use nasl_syntax::NaslValue;

/// A convenience function to obtain an optional, positional argument
/// from the `Register`.
pub fn get_optional_positional_arg<'a, T: FromNaslValue<'a>>(
    register: &'a Register,
    position: usize,
) -> Result<Option<T>, FunctionErrorKind> {
    register
        .positional()
        .get(position)
        .map(|arg| <T as FromNaslValue>::from_nasl_value(arg))
        .transpose()
}

/// A convenience function to obtain a positional argument
/// from the `Register`.
pub fn get_positional_arg<'a, T: FromNaslValue<'a>>(
    register: &'a Register,
    position: usize,
    num_required_positional_args: usize,
) -> Result<T, FunctionErrorKind> {
    let positional = register.positional();
    let arg = positional.get(position).ok_or_else(|| {
        let num_given = positional.len();
        FunctionErrorKind::MissingPositionalArguments {
            expected: num_required_positional_args,
            got: num_given,
        }
    })?;
    <T as FromNaslValue>::from_nasl_value(arg)
}

fn context_type_as_nasl_value<'a>(
    context_type: &'a ContextType,
    arg_name: &str,
) -> Result<&'a NaslValue, FunctionErrorKind> {
    match context_type {
        ContextType::Function(_, _) => Err(FunctionErrorKind::WrongArgument(format!(
            "Wrong argument for {}, expected a value, found a function.",
            arg_name
        ))),
        ContextType::Value(val) => Ok(val),
    }
}

/// A convenience function to obtain an optional, named argument
/// from the `Register`.
pub fn get_optional_named_arg<'a, T: FromNaslValue<'a>>(
    register: &'a Register,
    name: &'a str,
) -> Result<Option<T>, FunctionErrorKind> {
    register
        .named(name)
        .map(|arg| context_type_as_nasl_value(arg, name))
        .transpose()?
        .map(|arg| <T as FromNaslValue>::from_nasl_value(arg))
        .transpose()
}

/// A convenience function to obtain a named argument
/// from the `Register`.
pub fn get_named_arg<'a, T: FromNaslValue<'a>>(
    register: &'a Register,
    name: &'a str,
) -> Result<T, FunctionErrorKind> {
    let arg = register
        .named(name)
        .ok_or_else(|| FunctionErrorKind::MissingArguments(vec![name.to_string()]))?;
    <T as FromNaslValue>::from_nasl_value(context_type_as_nasl_value(arg, name)?)
}

/// A convenience function to obtain an optional, argument
/// that can be either positional or named from the `Register`.
pub fn get_optional_maybe_named_arg<'a, T: FromNaslValue<'a>>(
    register: &'a Register,
    name: &'a str,
    position: usize,
) -> Result<Option<T>, FunctionErrorKind> {
    let via_position = get_optional_positional_arg::<T>(register, position)?;
    if let Some(via_position) = via_position {
        Ok(Some(via_position))
    } else {
        get_optional_named_arg(register, name)
    }
}

/// A convenience function to obtain an argument
/// that can be either positional or named from the `Register`.
pub fn get_maybe_named_arg<'a, T: FromNaslValue<'a>>(
    register: &'a Register,
    name: &'a str,
    position: usize,
) -> Result<T, FunctionErrorKind> {
    let via_position = get_optional_positional_arg(register, position)?;
    if let Some(via_position) = via_position {
        Ok(via_position)
    } else {
        get_named_arg(register, name)
    }
}
