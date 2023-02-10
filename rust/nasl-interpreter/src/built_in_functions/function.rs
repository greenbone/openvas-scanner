// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Defines various built-in functions for NASL functions.

use sink::Sink;

use crate::{error::FunctionError, ContextType, NaslFunction, NaslValue, Register};

use super::resolve_positional_arguments;

/// NASL function to determine if a function is defined.
///
/// Uses the first positional argument to verify if a function is defined.
/// This argument must be a string everything else will return False per default.
/// Returns NaslValue::Boolean(true) when defined NaslValue::Boolean(false) otherwise.
pub fn defined_func(
    _: &str,
    _: &dyn Sink,
    register: &Register,
) -> Result<NaslValue, FunctionError> {
    let positional = resolve_positional_arguments(register);

    Ok(match positional.get(0) {
        Some(NaslValue::String(x)) => match register.named(x) {
            Some(ContextType::Function(_, _)) => true.into(),
            None => crate::lookup(x).is_some().into(),
            _ => false.into(),
        },
        _ => false.into(),
    })
}

/// Returns found function for key or None when not found
pub fn lookup(key: &str) -> Option<NaslFunction> {
    match key {
        "defined_func" => Some(defined_func),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use nasl_syntax::parse;
    use sink::DefaultSink;

    use crate::{Interpreter, NaslValue, NoOpLoader, Register};

    #[test]
    fn defined_func() {
        let code = r###"
        function b() { return 2; }
        defined_func("b");
        defined_func("defined_func");
        a = 12;
        defined_func("a");
        defined_func(a);
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null))); // defining function b
        assert_eq!(parser.next(), Some(Ok(true.into()))); // is b defined
        assert_eq!(parser.next(), Some(Ok(true.into()))); // is defined_func defined
        assert_eq!(parser.next(), Some(Ok(12i64.into()))); // defining variable a
        assert_eq!(parser.next(), Some(Ok(false.into()))); // is a a function
        assert_eq!(parser.next(), Some(Ok(false.into()))); // is the value of a a function
    }
}
