// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use nasl_builtin_utils::{error::FunctionErrorKind, get_named_parameter, NaslFunction};

use nasl_builtin_utils::{Context, Register};
use nasl_syntax::NaslValue;

/// NASL function to set a knowledge base
fn set_kb_item<K>(register: &Register, c: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let name = get_named_parameter(register, "name", true)?;
    let value = get_named_parameter(register, "value", true)?;
    let expires = match get_named_parameter(register, "expires", false) {
        Ok(NaslValue::Number(x)) => Some(*x as u64),
        Ok(NaslValue::Exit(_)) => None,
        Ok(x) => {
            return Err(FunctionErrorKind::Diagnostic(
                format!("expected expires to be a number but is {x}."),
                None,
            ))
        }
        Err(e) => return Err(e),
    };
    c.set_kb_item(name.to_string(), value.clone().as_primitive(), expires)
}

/// NASL function to get a knowledge base
fn get_kb_item<K>(register: &Register, c: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    match register.positional() {
        [x] => c.get_kb_item(&x.to_string()),
        x => Err(FunctionErrorKind::Diagnostic(
            format!("expected one positional argument but got: {}", x.len()),
            None,
        )),
    }
}

/// Returns found function for key or None when not found
pub fn lookup<K>(key: &str) -> Option<NaslFunction<K>> {
    match key {
        "set_kb_item" => Some(set_kb_item),
        "get_kb_item" => Some(get_kb_item),
        _ => None,
    }
}

pub struct KnowledgeBase;

impl<K> nasl_builtin_utils::NaslFunctionExecuter<K> for KnowledgeBase {
    fn nasl_fn_execute(
        &self,
        name: &str,
        register: &Register,
        context: &Context<K>,
    ) -> Option<nasl_builtin_utils::NaslResult> {
        lookup(name).map(|x| x(register, context))
    }

    fn nasl_fn_defined(&self, name: &str) -> bool {
        lookup::<&str>(name).is_some()
    }
}
