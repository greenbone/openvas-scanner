// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests;

use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

use crate::function_set;
use crate::nasl::syntax::NaslValue;
use crate::nasl::utils::error::FnError;
use crate::nasl::utils::Context;
use crate::storage::{Field, Kb, Retrieve};
use nasl_function_proc_macro::nasl_function;

#[derive(Debug, Error)]
pub enum KBError {
    #[error("Knowledge base item does not exist: {0}")]
    ItemNotFound(String),
    #[error("Multiple entries found for knowledge base item {0} where a single one was expected.")]
    MultipleItemsFound(String),
}

/// NASL function to set a value under name in a knowledge base
/// Only pushes unique values for the given name.
#[nasl_function(named(name, value, expires))]
fn set_kb_item(
    c: &Context,
    name: NaslValue,
    value: NaslValue,
    expires: Option<u64>,
) -> Result<NaslValue, FnError> {
    let expires = expires.map(|seconds| {
        let start = SystemTime::now();
        match start.duration_since(UNIX_EPOCH) {
            Ok(x) => x.as_secs() + seconds,
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
fn get_kb_item(c: &Context, key: &str) -> Result<NaslValue, FnError> {
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
fn replace_kb_item(c: &Context, name: NaslValue, value: NaslValue) -> Result<NaslValue, FnError> {
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
fn get_kb_list(c: &Context, key: NaslValue) -> Result<NaslValue, FnError> {
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
    (
        set_kb_item,
        get_kb_item,
        get_kb_list,
        replace_kb_item
    )
}
