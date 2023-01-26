//! Defines various built-in functions for NASL arrays and lists.
//!
//! In NASL a array is actually a dictionary capable of having not just indexable keys
//! while lists are standard arrays.

use std::collections::HashMap;

use sink::Sink;

use crate::{Register, NaslValue, error::FunctionError, NaslFunction};

use super::resolve_positional_arguments;


/// NASL function to create a dictionary out of an even number of arguments
///
/// Each uneven arguments out of positional arguments are used as keys while each even even argument is used a value.
/// When there is an uneven number of elements the last key will be dropped, as there is no corresponding value.
/// So `make_array(1, 0, 1)` will return the same response as `make_array(1, 0)`.
pub fn make_array(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    let positional = resolve_positional_arguments(register);
    let mut values = HashMap::new();
    for (idx, val) in positional.iter().enumerate() {
        if idx % 2 == 1 {
            values.insert(positional[idx -1].to_string(), val.clone());
        }
    }
    Ok(values.into())
}

/// Returns found function for key or None when not found
pub fn lookup(key: &str) -> Option<NaslFunction> {
    match key {
        "make_array" => Some(make_array),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use nasl_syntax::parse;
    use sink::DefaultSink;

    use crate::{Register, NoOpLoader, Interpreter, NaslValue};

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
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(parser.next(), Some(Ok(make_dict!(1 => 0i64, 2 => 1i64))));
        assert_eq!(parser.next(), Some(Ok(make_dict!(1 => 0i64, 2 => 1i64))));
        assert_eq!(parser.next(), Some(Ok(make_dict!())));
        assert_eq!(parser.next(), Some(Ok(make_dict!())));
    }
}
