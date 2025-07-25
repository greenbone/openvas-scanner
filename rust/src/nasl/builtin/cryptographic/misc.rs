// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::nasl::prelude::*;

#[nasl_function]
fn insert_hexzeros(register: &Register) -> Result<Vec<u8>, FnError> {
    // As in is a keyword in rust, we cannot use the nasl_function annotation for named arguments.
    let data = register
        .named("in")
        .ok_or_else(|| ArgumentError::MissingNamed(vec!["in".into()]))?;
    let data = match data {
        ContextType::Value(NaslValue::Data(x)) => x,
        ContextType::Value(NaslValue::String(x)) => x.as_bytes(),
        _ => return Err(ArgumentError::WrongArgument("expected Data.".to_string()).into()),
    };

    let mut result = vec![];
    for byte in data {
        if *byte == 0 {
            break;
        }
        result.push(*byte);
        result.push(0);
    }
    Ok(result)
}

pub struct Misc;

function_set! {
    Misc,
    (
        (insert_hexzeros, "insert_hexzeros"),
    )
}
