// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Defines various built-in functions for NASL arrays and lists.
//!
//! In NASL a array is actually a dictionary capable of having not just indexable keys
//! while lists are standard arrays.

use std::collections::HashMap;

use crate::{error::FunctionErrorKind, Context, NaslFunction, NaslValue, Register};

use super::resolve_positional_arguments;

/// NASL function to create a dictionary out of an even number of arguments
///
/// Each uneven arguments out of positional arguments are used as keys while each even even argument is used a value.
/// When there is an uneven number of elements the last key will be dropped, as there is no corresponding value.
/// So `make_array(1, 0, 1)` will return the same response as `make_array(1, 0)`.
pub fn make_array<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
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
pub fn make_list<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let values = nasl_make_list(register)?;
    Ok(NaslValue::Array(values))
}

/// NASL function to sorts the values of a dict/array. WARNING: drops the keys of a dict and returns an array.
pub fn nasl_sort<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let mut values = nasl_make_list(register)?;
    values.sort();
    Ok(NaslValue::Array(values))
}

/// Returns an array with the keys of a dict
pub fn keys<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
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
pub fn max_index<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
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
pub fn lookup<K>(key: &str) -> Option<NaslFunction<K>> {
    match key {
        "make_array" => Some(make_array),
        "make_list" => Some(make_list),
        "sort" => Some(nasl_sort),
        "keys" => Some(keys),
        "max_index" => Some(max_index),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use nasl_syntax::parse;
    use std::collections::HashMap;

    use crate::{DefaultContext, Interpreter, NaslValue, Register};

    macro_rules! make_dict {
        ($($key:expr => $val:expr),*) => {
            {
                #[allow(unused_mut)]
                let mut result: HashMap<String, NaslValue> = HashMap::new();
                $(
                   let key: String = format!("{}", $key);
                   let value: NaslValue = $val.into();
                   result.insert(key, value);
                )*
                let result: NaslValue = result.into();
                result
            }
        };
    }

    #[test]
    fn make_array() {
        let code = r###"
        make_array(1, 0, 2, 1);
        make_array(1, 0, 2, 1, 1);
        make_array(1);
        make_array();
        "###;
        let mut register = Register::default();
        let binding = DefaultContext::default();
        let context = binding.as_context();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(parser.next(), Some(Ok(make_dict!(1 => 0i64, 2 => 1i64))));
        assert_eq!(parser.next(), Some(Ok(make_dict!(1 => 0i64, 2 => 1i64))));
        assert_eq!(parser.next(), Some(Ok(make_dict!())));
        assert_eq!(parser.next(), Some(Ok(make_dict!())));
    }

    #[test]
    fn make_list() {
        let code = r###"
        a = [2,4];
        make_list(1, 0);
        make_list();
        make_list(1,NULL,2);
        b = make_array("el", 6);
        make_list(1, 0, b);
        make_list(1, 0, a);
        "###;
        let mut register = Register::default();
        let binding = DefaultContext::default();
        let context = binding.as_context();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Array(vec![
                NaslValue::Number(2),
                NaslValue::Number(4)
            ])))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Array(vec![
                NaslValue::Number(1),
                NaslValue::Number(0)
            ])))
        );
        assert_eq!(parser.next(), Some(Ok(NaslValue::Array([].into()))));
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Array(vec![
                NaslValue::Number(1),
                NaslValue::Number(2)
            ])))
        );
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Array(vec![
                NaslValue::Number(1),
                NaslValue::Number(0),
                NaslValue::Number(6)
            ])))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Array(vec![
                NaslValue::Number(1),
                NaslValue::Number(0),
                NaslValue::Number(2),
                NaslValue::Number(4)
            ])))
        );
    }

    #[test]
    fn sort() {
        let code = r###"
        a = make_array(5, 6, 7, 8);
        l = make_list("abbb", 1, "aaaa", 0, a);
        s = sort(l);
        "###;
        let mut register = Register::default();
        let binding = DefaultContext::default();
        let context = binding.as_context();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        parser.next();
        parser.next();
        let a = parser.next();
        let b = Some(Ok(NaslValue::Array(vec![
            NaslValue::Number(0),
            NaslValue::Number(1),
            NaslValue::Number(6),
            NaslValue::Number(8),
            NaslValue::String("aaaa".to_string()),
            NaslValue::String("abbb".to_string()),
        ])));
        assert_eq!(a, b);
    }

    #[test]
    fn keys() {
        let code = r###"
        a = make_array("a", 6);
        l = make_list("foo", "bar");
        keys(a,l);
        "###;
        let mut register = Register::default();
        let binding = DefaultContext::default();
        let context = binding.as_context();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        parser.next();
        parser.next();
        let a = parser.next();
        let b = Some(Ok(NaslValue::Array(vec![
            NaslValue::String("a".to_string()),
            NaslValue::Number(0),
            NaslValue::Number(1),
        ])));

        assert_eq!(a, b);
    }

    #[test]
    fn max_index() {
        let code = r###"
        l = [1,2,3,4,5];
        max_index(l);
        max_index(make_array(1,2,3,4,5,6,7));
        max_index(make_list(1, 0));
        max_index(make_list());
        "###;
        let mut register = Register::default();
        let binding = DefaultContext::default();
        let context = binding.as_context();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        parser.next();
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(5))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(3))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(2))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(0))));
    }
}
