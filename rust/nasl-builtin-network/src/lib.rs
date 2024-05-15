// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use nasl_builtin_utils::{Context, FunctionErrorKind, NaslResult, Register};
use nasl_syntax::NaslValue;
use storage::Field;

pub mod socket;

fn get_named_value(r: &Register, name: &str) -> Result<NaslValue, FunctionErrorKind> {
    match r.named(name) {
        Some(x) => match x {
            nasl_builtin_utils::ContextType::Function(_, _) => {
                Err(FunctionErrorKind::MissingArguments(vec![name.to_string()]))
            }
            nasl_builtin_utils::ContextType::Value(val) => Ok(val.to_owned()),
        },
        None => Err(FunctionErrorKind::MissingArguments(vec![
            "socket".to_string()
        ])),
    }
}

fn get_usize(r: &Register, name: &str) -> Result<usize, FunctionErrorKind> {
    match get_named_value(r, name)? {
        NaslValue::Number(num) => {
            if num < 0 {
                return Err(FunctionErrorKind::WrongArgument(format!(
                    "Argument {name} must be >= 0"
                )));
            }
            Ok(num as usize)
        }
        _ => Err(FunctionErrorKind::WrongArgument(
            "Wrong type for argument, expected a number".to_string(),
        )),
    }
}

fn get_data(r: &Register) -> Result<Vec<u8>, FunctionErrorKind> {
    Ok((&get_named_value(r, "data")?).into())
}

fn get_opt_int(r: &Register, name: &str) -> i64 {
    get_named_value(r, name)
        .map(|val| match val {
            NaslValue::Number(len) => len,
            _ => 0,
        })
        .unwrap_or_default()
}

pub fn get_kb_item<K>(context: &Context<K>, name: &str) -> NaslResult {
    context
        .retriever()
        .retrieve(context.key(), storage::Retrieve::KB(name.to_string()))
        .map(|r| {
            r.into_iter().find_map(|x| match x {
                Field::NVT(_) | Field::NotusAdvisory(_) => None,
                Field::KB(kb) => kb.value.into(),
            })
        })
        .map(|x| match x {
            Some(x) => x.into(),
            None => NaslValue::Null,
        })
        .map_err(|e| e.into())
}
