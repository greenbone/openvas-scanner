// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later
use std::time::{SystemTime, UNIX_EPOCH};

use storage::{Field, Kb, Retrieve};

use crate::{error::FunctionErrorKind, Context, NaslFunction, NaslValue, Register};

use super::get_named_parameter;

/// NASL function to set a knowledge base
fn set_kb_item<K>(register: &Register, c: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let name = get_named_parameter(register, "name", true)?;
    let value = get_named_parameter(register, "value", true)?;
    let expires = match get_named_parameter(register, "expires", false) {
        Ok(NaslValue::Number(x)) => Some(*x),
        Ok(NaslValue::Exit(0)) => None,
        Ok(x) => {
            return Err(FunctionErrorKind::Diagnostic(
                format!("expected expires to be a number but is {x}."),
                None,
            ))
        }
        Err(e) => return Err(e),
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
fn get_kb_item<K>(register: &Register, c: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    match register.positional() {
        [x] => c
            .retriever()
            .retrieve(c.key(), &Retrieve::KB(x.to_string()))
            .map(|r| {
                r.into_iter().find_map(|x| match x {
                    Field::NVT(_) => None,
                    Field::KB(kb) => kb.value.into(),
                })
            })
            .map(|x| match x {
                Some(x) => x.into(),
                None => NaslValue::Null,
            })
            .map_err(|e| e.into()),
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

#[cfg(test)]
mod tests {
    use nasl_syntax::parse;

    use crate::{DefaultContext, Interpreter, NaslValue, Register};

    #[test]
    fn set_kb_item() {
        let code = r###"
        set_kb_item(name: "test", value: 1);
        set_kb_item(name: "test");
        set_kb_item(value: 1);
        "###;
        let mut register = Register::default();
        let binding = DefaultContext::default();
        let context = binding.as_context();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
        assert!(matches!(parser.next(), Some(Err(_))));
        assert!(matches!(parser.next(), Some(Err(_))));
    }
    #[test]
    fn get_kb_item() {
        let code = r###"
        set_kb_item(name: "test", value: 1);
        get_kb_item("test");
        get_kb_item("test", 1);
        "###;
        let mut register = Register::default();
        let binding = DefaultContext::default();
        let context = binding.as_context();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(1))));
        assert!(matches!(parser.next(), Some(Err(_))));
    }
}
