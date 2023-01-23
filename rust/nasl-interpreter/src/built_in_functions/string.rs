//! Defines NASL functions that deal with string and their helpers

use core::fmt::{self, Write};
use sink::Sink;

use crate::{
    error::FunctionError, lookup_keys::FC_ANON_ARGS, ContextType, NaslFunction, NaslValue, Register,
};

fn resolve_positional_arguments(register: &Register) -> Vec<NaslValue> {
    match register.named(FC_ANON_ARGS).cloned() {
        // TODO maybe we need to resolve those nasl values?
        Some(ContextType::Value(NaslValue::Array(arr))) => arr,
        _ => vec![],
    }
}

impl From<fmt::Error> for FunctionError {
    fn from(e: fmt::Error) -> Self {
        Self {
            reason: format!("{}", e),
        }
    }
}

fn write_nasl_value(s: &mut String, value: &NaslValue) -> Result<(), FunctionError> {
    match value {
        NaslValue::String(x) => write!(s, "{}", x),
        NaslValue::Number(x) => {
            let c = *x as u8 as char;
            if c.is_ascii_graphic() {
                write!(s, "{}", c)
            } else {
                write!(s, ".")
            }
        }
        NaslValue::Array(x) => {
            for p in x {
                write_nasl_value(s, p)?;
            }
            Ok(())
        }
        NaslValue::Dict(x) => {
            for p in x.values() {
                write_nasl_value(s, p)?;
            }
            Ok(())
        }
        _ => write!(s, "."),
    }?;
    Ok(())
}

/// NASL function to return uppercase equivalent of a given string
///
/// If this function retrieves anything but a string it returns NULL
fn toupper(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    let positional = resolve_positional_arguments(register);
    Ok(match positional.get(0) {
        Some(NaslValue::String(x)) => x.to_uppercase().into(),
        _ => NaslValue::Null,
    })
}

/// NASL function to return lowercase equivalent of a given string
///
/// If this function retrieves anything but a string it returns NULL
fn tolower(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    let positional = resolve_positional_arguments(register);
    Ok(match positional.get(0) {
        Some(NaslValue::String(x)) => x.to_lowercase().into(),
        _ => NaslValue::Null,
    })
}

/// NASL function to parse numeric values into characters and combine with additional values
fn raw_string(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    let positional = resolve_positional_arguments(register);
    let mut s = String::with_capacity(2 * positional.len());
    for p in positional {
        write_nasl_value(&mut s, &p)?;
    }
    Ok(s.into())
}

/// NASL function to return  a hex presentation of given string as a positional argument.
///
/// If the positional arguments are empty it reutnrns NaslValue::Null.
/// It only uses the first positional argument and when it is not a NaslValue:String than it returns NaslValue::Null.
fn hexstr(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    let positional = resolve_positional_arguments(register);
    // we already checked that positional has at least one argument
    Ok(match positional.get(0) {
        Some(NaslValue::String(x)) => {
            let mut s = String::with_capacity(2 * x.len());
            for byte in x.as_bytes() {
                write!(s, "{:02X}", byte)?;
            }
            s.into()
        }
        _ => NaslValue::Null,
    })
}

/// Returns found function for key or None when not found
pub fn lookup(key: &str) -> Option<NaslFunction> {
    match key {
        "hexstr" => Some(hexstr),
        "raw_string" => Some(raw_string),
        "tolower" => Some(tolower),
        "toupper" => Some(toupper),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use nasl_syntax::parse;
    use sink::DefaultSink;

    use crate::{Interpreter, NaslValue, NoOpLoader, Register};

    #[test]
    fn hexstr() {
        let code = r###"
        a = 'foo';
        hexstr('foo');
        hexstr('foo', "I will be ignored");
        hexstr(6);
        hexstr();
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        parser.next();
        assert_eq!(parser.next(), Some(Ok("666F6F".into())));
        assert_eq!(parser.next(), Some(Ok("666F6F".into())));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
    }
    #[test]
    fn raw_string() {
        let code = r###"
        raw_string(0x7B);
        raw_string(0x7B, 1);
        raw_string(0x7B, 1, "Hallo");
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(parser.next(), Some(Ok("{".into())));
        assert_eq!(parser.next(), Some(Ok("{.".into())));
        assert_eq!(parser.next(), Some(Ok("{.Hallo".into())));
    }
    #[test]
    fn tolower() {
        let code = r###"
        tolower(0x7B);
        tolower('HALLO');
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
        assert_eq!(parser.next(), Some(Ok("hallo".into())));
    }
    #[test]
    fn toupper() {
        let code = r###"
        toupper(0x7B);
        toupper('hallo');
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
        assert_eq!(parser.next(), Some(Ok("HALLO".into())));
    }
}
