// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines various built-in functions for NASL arrays and lists.
//!
//! In NASL a array is actually a dictionary capable of having not just indexable keys
//! while lists are standard arrays.

#[cfg(test)]
mod tests;

use std::collections::HashMap;

use crate::nasl::prelude::*;

/// NASL function to create a dictionary out of an even number of arguments
///
/// Each uneven arguments out of positional arguments are used as keys while each even even argument is used a value.
/// When there is an uneven number of elements the last key will be dropped, as there is no corresponding value.
/// So `make_array(1, 0, 1)` will return the same response as `make_array(1, 0)`.
#[nasl_function]
fn make_array(positionals: CheckedPositionals<NaslValue>) -> HashMap<String, NaslValue> {
    let mut values = HashMap::new();
    for (idx, val) in positionals.iter().enumerate() {
        if idx % 2 == 1 {
            values.insert(positionals[idx - 1].to_string(), val.clone());
        }
    }
    values
}

fn create_list(positionals: CheckedPositionals<NaslValue>) -> Vec<NaslValue> {
    let mut values = Vec::<NaslValue>::new();
    for val in positionals.iter() {
        match val {
            NaslValue::Dict(x) => values.extend(x.values().cloned().collect::<Vec<NaslValue>>()),
            NaslValue::Array(x) => values.extend(x.clone()),
            NaslValue::Null => {}
            x => values.push(x.clone()),
        }
    }
    values
}
/// NASL function to create a list out of a number of unnamed arguments
#[nasl_function]
fn make_list(positionals: CheckedPositionals<NaslValue>) -> Vec<NaslValue> {
    create_list(positionals)
}

/// NASL function to sorts the values of a dict/array. WARNING: drops the keys of a dict and returns an array.
#[nasl_function]
fn nasl_sort(positionals: CheckedPositionals<NaslValue>) -> Vec<NaslValue> {
    let mut values = create_list(positionals);
    values.sort();
    values
}

/// Returns an array with the keys of a dict
#[nasl_function]
fn keys(positionals: Positionals<NaslValue>) -> Option<Vec<NaslValue>> {
    let mut keys = vec![];
    for val in positionals.iter() {
        match val.unwrap() {
            NaslValue::Dict(x) => keys.extend(x.keys().map(|a| NaslValue::from(a.to_string()))),
            NaslValue::Array(x) => keys.extend((0..(x.len() as i64)).map(NaslValue::from)),
            _ => return None,
        }
    }
    Some(keys)
}

/// NASL function to return the length of an array|dict.
#[nasl_function]
fn max_index(arr: &NaslValue) -> Option<usize> {
    match arr {
        NaslValue::Dict(x) => Some(x.len()),
        NaslValue::Array(x) => Some(x.len()),
        _ => None,
    }
}

pub struct Array;

function_set! {
    Array,
    (
        make_array,
        make_list,
        (nasl_sort, "sort"),
        keys,
        max_index,
    )
}
