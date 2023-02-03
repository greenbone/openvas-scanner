// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Defines NASL miscellaneous functions

use std::{fs::File, io::Read};

use sink::Sink;

use crate::{error::FunctionError, ContextType, NaslFunction, NaslValue, Register};

#[inline]
#[cfg(unix)]
/// Reads 8 bytes from /dev/urandom and parses it to an i64
fn random_impl() -> Result<i64, FunctionError> {
    let mut rng = File::open("/dev/urandom")
        .map_err(|e| FunctionError::new("randr", e.kind().into()))?;
    let mut buffer = [0u8; 8];
    rng.read_exact(&mut buffer)
        .map(|_| i64::from_be_bytes(buffer))
        .map_err(|e| FunctionError::new("randr", e.kind().into()))
}

/// NASL function to get random number
pub fn rand(_: &str, _: &dyn Sink, _: &Register) -> Result<NaslValue, FunctionError> {
    random_impl().map(NaslValue::Number)
}

/// NASL function to get host byte order
pub fn get_byte_order(_: &str, _: &dyn Sink, _: &Register) -> Result<NaslValue, FunctionError> {
    Ok(NaslValue::Boolean(cfg!(target_endian = "little")))
}

/// NASL function to convert given number to string
pub fn dec2str(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    match register.named("num") {
        Some(ContextType::Value(NaslValue::Number(x))) => Ok(NaslValue::String(x.to_string())),
        x => Err(FunctionError::new("dec2str", ("0", "numeric", x).into())),
    }
}

/// Returns found function for key or None when not found
pub fn lookup(key: &str) -> Option<NaslFunction> {
    match key {
        "rand" => Some(rand),
        "get_byte_order" => Some(get_byte_order),
        "dec2str" => Some(dec2str),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use nasl_syntax::parse;
    use sink::DefaultSink;

    use crate::{Interpreter, NaslValue, NoOpLoader, Register};

    #[test]
    fn rand() {
        let code = r###"
        rand();
        rand();
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        let first = parser.next();
        let second = parser.next();
        assert!(matches!(first, Some(Ok(NaslValue::Number(_)))));
        assert!(matches!(second, Some(Ok(NaslValue::Number(_)))));
        assert_ne!(first, second);
    }

    #[test]
    fn get_byte_order() {
        let code = r###"
        get_byte_order();
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert!(matches!(parser.next(), Some(Ok(NaslValue::Boolean(_)))));
    }

    #[test]
    fn dec2str() {
        let code = r###"
        dec2str(num: 23);
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(parser.next(), Some(Ok("23".into())));
    }
}
