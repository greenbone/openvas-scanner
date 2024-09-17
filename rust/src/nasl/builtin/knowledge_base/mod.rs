// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests;

use std::time::{SystemTime, UNIX_EPOCH};

use crate::function_set;
use crate::nasl::syntax::NaslValue;
use crate::nasl::utils::error::FunctionErrorKind;
use crate::nasl::utils::Context;
use crate::storage::{Field, Kb, Retrieve};
use nasl_function_proc_macro::nasl_function;

/// NASL function to set a value under name in a knowledge base
/// Only pushes unique values for the given name.
#[nasl_function(named(name, value, expires))]
fn set_kb_item(
    c: &Context,
    name: NaslValue,
    value: NaslValue,
    expires: Option<NaslValue>,
) -> Result<NaslValue, FunctionErrorKind> {
    let expires = match expires {
        Some(NaslValue::Number(x)) => Some(x),
        Some(NaslValue::Exit(0)) => None,
        None => None,
        Some(x) => {
            return Err(FunctionErrorKind::Diagnostic(
                format!("expected expires to be a number but is {x}."),
                None,
            ))
        }
    }
    .map(|seconds| {
        let start = SystemTime::now();
        match start.duration_since(UNIX_EPOCH) {
            Ok(x) => x.as_secs() + seconds as u64,
            Err(_) => 0,
        }
    });
    c.dispatcher()
        .dispatch(
            c.key(),
            Field::KB(Kb {
                key: name.to_string(),
                value: value.clone().as_primitive(),
                expire: expires,
            }),
        )
        .map(|_| NaslValue::Null)
        .map_err(|e| e.into())
}

/// NASL function to get a knowledge base
#[nasl_function]
fn get_kb_item(c: &Context, key: &str) -> Result<NaslValue, FunctionErrorKind> {
    c.retriever()
        .retrieve(c.key(), Retrieve::KB(key.to_string()))
        .map(|r| {
            r.into_iter()
                .filter_map(|x| match x {
                    Field::NVT(_) | Field::NotusAdvisory(_) | Field::Result(_) => None,
                    Field::KB(kb) => Some(kb.value.into()),
                })
                .collect::<Vec<_>>()
        })
        .map(NaslValue::Fork)
        .map_err(|e| e.into())
}

/// NASL function to replace a kb list
#[nasl_function(named(name, value))]
fn replace_kb_item(
    c: &Context,
    name: NaslValue,
    value: NaslValue,
) -> Result<NaslValue, FunctionErrorKind> {
    c.dispatcher()
        .dispatch_replace(
            c.key(),
            Field::KB(Kb {
                key: name.to_string(),
                value: value.clone().as_primitive(),
                expire: None,
            }),
        )
        .map(|_| NaslValue::Null)
        .map_err(|e| e.into())
}

/// NASL function to retrieve an item in a KB.
#[nasl_function]
fn get_kb_list(c: &Context, key: NaslValue) -> Result<NaslValue, FunctionErrorKind> {
    c.retriever()
        .retrieve(c.key(), Retrieve::KB(key.to_string()))
        .map(|r| {
            r.into_iter()
                .filter_map(|x| match x {
                    Field::NVT(_) | Field::NotusAdvisory(_) | Field::Result(_) => None,
                    Field::KB(kb) => Some(kb.value.into()),
                })
                .collect::<Vec<_>>()
        })
        .map(NaslValue::Array)
        .map_err(|e| e.into())
}

pub struct KnowledgeBase;

function_set! {
    KnowledgeBase,
    sync_stateless,
    (
        set_kb_item,
        get_kb_item,
        get_kb_list,
        replace_kb_item
    )
}
