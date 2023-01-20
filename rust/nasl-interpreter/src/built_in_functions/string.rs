//! Defines NASL functions that deal with string and their helpers

use core::fmt::Write;
use sink::Sink;

use crate::{
    error::FunctionError, lookup_keys::FC_ANON_ARGS, ContextType, NaslFunction, NaslValue, Register,
};

pub fn resolve_positional_arguments(register: &Register) -> Vec<NaslValue> {
    match register.named(FC_ANON_ARGS).cloned() {
        // TODO maybe we need to resolve those nasl values?
        Some(ContextType::Value(NaslValue::Array(arr))) => arr,
        _ => vec![],
    }
}

/// NASL function to return  a hex presentation of given string as a positional argument.
///
/// If the positional arguments are empty it reutnrns NaslValue::Null.
/// It only uses the first positional argument and when it is not a NaslValue:String than it returns NaslValue::Null.
pub fn hexstr(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    let positional = resolve_positional_arguments(register);
    // we already checked that positional has at least one argument
    Ok(match positional.get(0) {
        Some(NaslValue::String(x)) => {
            let mut s = String::with_capacity(2 * x.len());
            for byte in x.as_bytes() {
                match write!(s, "{:02X}", byte) {
                    Ok(_) => {}
                    Err(e) => {
                        return Err(FunctionError {
                            reason: format!("Unable to parse {} to hex: {}", byte, e),
                        })
                    }
                };
            }
            NaslValue::String(s)
        }
        _ => NaslValue::Null,
    })
}

/// Returns found function for key or None when not found
pub fn lookup(key: &str) -> Option<NaslFunction> {
    match key {
        "hexstr" => Some(hexstr),
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
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::String("666F6F".to_owned())))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::String("666F6F".to_owned())))
        );
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
    }
}
