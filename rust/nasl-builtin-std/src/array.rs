// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines various built-in functions for NASL arrays and lists.
//!
//! In NASL a array is actually a dictionary capable of having not just indexable keys
//! while lists are standard arrays.

use std::collections::HashMap;

use nasl_builtin_utils::error::FunctionErrorKind;

use nasl_builtin_utils::{Context, NaslFunction, Register};
use nasl_syntax::NaslValue;

use nasl_builtin_utils::resolve_positional_arguments;

/// NASL function to create a dictionary out of an even number of arguments
///
/// Each uneven arguments out of positional arguments are used as keys while each even even argument is used a value.
/// When there is an uneven number of elements the last key will be dropped, as there is no corresponding value.
/// So `make_array(1, 0, 1)` will return the same response as `make_array(1, 0)`.
fn make_array<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let positional = resolve_positional_arguments(register);
    let mut values = HashMap::new();
    for (idx, val) in positional.iter().enumerate() {
        if idx % 2 == 1 {
            values.insert(positional[idx - 1].to_string(), val.clone());
        }
    }
    Ok(values.into())
}

/// NASL function to create a list out of a number of unnamed arguments
fn nasl_make_list(register: &Register) -> Result<Vec<NaslValue>, FunctionErrorKind> {
    let arr = resolve_positional_arguments(register);
    let mut values = Vec::<NaslValue>::new();
    for val in arr.iter() {
        match val {
            NaslValue::Dict(x) => values.extend(x.values().cloned().collect::<Vec<NaslValue>>()),
            NaslValue::Array(x) => values.extend(x.clone()),
            NaslValue::Null => {}
            x => values.push(x.clone()),
        }
    }
    Ok(values)
}
/// NASL function to create a list out of a number of unnamed arguments
fn make_list<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let values = nasl_make_list(register)?;
    Ok(NaslValue::Array(values))
}

/// NASL function to sorts the values of a dict/array. WARNING: drops the keys of a dict and returns an array.
fn nasl_sort<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let mut values = nasl_make_list(register)?;
    values.sort();
    Ok(NaslValue::Array(values))
}

/// Returns an array with the keys of a dict
fn keys<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let positional = resolve_positional_arguments(register);
    let mut keys = Vec::<NaslValue>::new();
    for val in positional.iter() {
        match val {
            NaslValue::Dict(x) => keys.extend(x.keys().map(|a| NaslValue::from(a.to_string()))),
            NaslValue::Array(x) => keys.extend((0..(x.len() as i64)).map(NaslValue::from)),
            _ => return Ok(NaslValue::Null),
        }
    }

    Ok(NaslValue::Array(keys))
}

/// NASL function to return the length of an array|dict.
fn max_index<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let positional = register.positional();
    if positional.is_empty() {
        return Ok(NaslValue::Null);
    };

    match &positional[0] {
        NaslValue::Dict(x) => Ok(NaslValue::Number(x.len() as i64)),
        NaslValue::Array(x) => Ok(NaslValue::Number(x.len() as i64)),
        _ => Ok(NaslValue::Null),
    }
}

/// Returns found function for key or None when not found
pub(crate) fn lookup<K>(key: &str) -> Option<NaslFunction<K>> {
    match key {
        "make_array" => Some(make_array),
        "make_list" => Some(make_list),
        "sort" => Some(nasl_sort),
        "keys" => Some(keys),
        "max_index" => Some(max_index),
        _ => None,
    }
}
