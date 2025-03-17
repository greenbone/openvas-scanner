// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests;

use thiserror::Error;

use crate::function_set;
use crate::nasl::syntax::NaslValue;
use crate::nasl::utils::Context;
use crate::nasl::utils::error::FnError;
use crate::storage::items::kb::KbKey;
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
) -> Result<(), FnError> {
    let _ = expires;
    c.set_kb_item(KbKey::Custom(name.to_string()), value.as_kb())
}

/// NASL function to get a knowledge base
#[nasl_function]
fn get_kb_item(c: &Context, key: &str) -> Result<NaslValue, FnError> {
    let kbs = c.get_kb_item(&KbKey::Custom(key.to_string()))?;
    let ret = NaslValue::Fork(kbs.into_iter().map(NaslValue::from).collect());

    Ok(ret)
}

/// NASL function to replace a kb list
#[nasl_function(named(name, value))]
fn replace_kb_item(c: &Context, name: NaslValue, value: NaslValue) -> Result<(), FnError> {
    c.set_single_kb_item(KbKey::Custom(name.to_string()), value.as_kb())
}

/// NASL function to retrieve an item in a KB.
#[nasl_function]
fn get_kb_list(c: &Context, key: &str) -> Result<NaslValue, FnError> {
    let kbs = c.get_kb_item(&KbKey::Custom(key.to_string()))?;
    let ret = NaslValue::Array(kbs.into_iter().map(NaslValue::from).collect());

    Ok(ret)
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
