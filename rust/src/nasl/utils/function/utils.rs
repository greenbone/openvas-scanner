// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Convenience functions, used internally in the `NaslFunctionArg` macro.

use super::super::lookup_keys::FC_ANON_ARGS;

use crate::nasl::prelude::*;

/// A convenience function to obtain an optional, positional argument
/// from the `Register`.
pub fn get_optional_positional_arg<'a, T: FromNaslValue<'a>>(
    register: &'a Register,
    position: usize,
) -> Result<Option<T>, FnError> {
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
) -> Result<T, FnError> {
    let positional = register.positional();
    let arg = positional.get(position).ok_or_else(|| {
        let num_given = positional.len();
        ArgumentError::MissingPositionals {
            expected: num_required_positional_args,
            got: num_given,
        }
    })?;
    <T as FromNaslValue>::from_nasl_value(arg)
}

fn context_type_as_nasl_value<'a>(
    context_type: &'a ContextType,
    arg_name: &str,
) -> Result<&'a NaslValue, ArgumentError> {
    match context_type {
        ContextType::Function(_, _) => Err(ArgumentError::WrongArgument(format!(
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
) -> Result<Option<T>, FnError> {
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
) -> Result<T, FnError> {
    let arg = register
        .named(name)
        .ok_or_else(|| ArgumentError::MissingNamed(vec![name.to_string()]))?;
    <T as FromNaslValue>::from_nasl_value(context_type_as_nasl_value(arg, name)?)
}

/// A convenience function to obtain an optional, argument
/// that can be either positional or named from the `Register`.
pub fn get_optional_maybe_named_arg<'a, T: FromNaslValue<'a>>(
    register: &'a Register,
    name: &'a str,
    position: usize,
) -> Result<Option<T>, FnError> {
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
) -> Result<T, FnError> {
    let via_position = get_optional_positional_arg(register, position)?;
    if let Some(via_position) = via_position {
        Ok(via_position)
    } else {
        get_named_arg(register, name)
    }
}

/// Check that named and maybe_named arguments account for
/// all given named arguments (i.e. no additional, unknown
/// arguments exist).
/// Return the number of maybe named arguments that were given
/// as a named argument.
fn check_named_args(
    register: &Register,
    _nasl_fn_name: &str,
    named: &[&str],
    maybe_named: &[&str],
) -> Result<usize, FnError> {
    let mut num_maybe_named = 0;
    for arg_name in register.iter_named_args().unwrap() {
        if arg_name == FC_ANON_ARGS || named.contains(&arg_name) {
            continue;
        } else if maybe_named.contains(&arg_name) {
            num_maybe_named += 1;
        } else {
            #[cfg(feature = "enforce-no-trailing-arguments")]
            return Err(ArgumentError::UnexpectedArgument(arg_name.into()).into());
            #[cfg(not(feature = "enforce-no-trailing-arguments"))]
            tracing::debug!(
                "Unexpected named argument '{arg_name}' in NASL function {_nasl_fn_name}."
            );
        }
    }
    Ok(num_maybe_named)
}

/// Check that the number of expected positional arguments given to a
/// NASL function matches the actual number given, and that all given
/// named arguments exist.
pub fn check_args(
    register: &Register,
    _nasl_fn_name: &str,
    named: &[&str],
    maybe_named: &[&str],
    max_num_expected_positional: Option<usize>,
) -> Result<(), FnError> {
    let num_maybe_named_given = check_named_args(register, _nasl_fn_name, named, maybe_named)?;
    let num_positional_given = register.positional().len();
    if let Some(max_num_expected_positional) = max_num_expected_positional {
        let num_positional_expected = max_num_expected_positional - num_maybe_named_given;
        if num_positional_given > num_positional_expected {
            #[cfg(feature = "enforce-no-trailing-arguments")]
            return Err(ArgumentError::TrailingPositionals {
                expected: num_positional_expected,
                got: num_positional_given,
            }
            .into());
            #[cfg(not(feature = "enforce-no-trailing-arguments"))]
            tracing::debug!(
                "Trailing positional arguments in NASL function {_nasl_fn_name}. Expected {num_positional_expected}, found {num_positional_given}"
            );
        }
    }
    Ok(())
}
