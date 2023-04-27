// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::{
    error::FunctionErrorKind, lookup_keys::FC_ANON_ARGS, ContextType, NaslFunction, NaslValue,
    Register,
};

mod array;
mod cryptography;
mod description;
mod frame_forgery;
mod function;
mod hostname;
mod kb;
mod misc;
mod ssh;
mod string;

pub(crate) fn resolve_positional_arguments(register: &Register) -> Vec<NaslValue> {
    match register.named(FC_ANON_ARGS).cloned() {
        Some(ContextType::Value(NaslValue::Array(arr))) => arr,
        _ => vec![],
    }
}

/// gets a named parameter
///
/// The function name is required for the error cases that can occur when either the found
/// parameter is a function or when required is set to true and no parameter was found.
///
/// Additionally when a parameter is not required it will return Exit(0) instead of Null. This is
/// done to allow differentiation between a parameter that is set to Null on purpose.
pub(crate) fn get_named_parameter<'a>(
    registrat: &'a Register,
    key: &'a str,
    required: bool,
) -> Result<&'a NaslValue, FunctionErrorKind> {
    match registrat.named(key) {
        None => {
            if required {
                Err(FunctionErrorKind::MissingArguments(vec![key.to_owned()]))
            } else {
                // we use exit because a named value can be intentionally set to null and may be
                // treated differently when it is not set compared to set but null.
                Ok(&NaslValue::Exit(0))
            }
        }
        Some(ct) => match ct {
            ContextType::Value(value) => Ok(value),
            _ => Err((key, "value", "function").into()),
        },
    }
}

pub(crate) fn lookup<K>(function_name: &str) -> Option<NaslFunction<K>>
where
    K: AsRef<str>,
{
    description::lookup(function_name)
        .or_else(|| kb::lookup(function_name))
        .or_else(|| hostname::lookup(function_name))
        .or_else(|| misc::lookup(function_name))
        .or_else(|| string::lookup(function_name))
        .or_else(|| array::lookup(function_name))
        .or_else(|| function::lookup(function_name))
        .or_else(|| cryptography::lookup(function_name))
        .or_else(|| frame_forgery::lookup(function_name))
        .or_else(|| ssh::lookup(function_name))
}
