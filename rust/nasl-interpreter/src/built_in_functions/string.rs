// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Defines NASL functions that deal with string and their helpers

use core::fmt::Write;
use sink::Sink;

use crate::{context::ContextType, error::FunctionError, NaslFunction, NaslValue, Register};

use super::resolve_positional_arguments;

fn append_nasl_value_as_u8(data: &mut Vec<u8>, p: &NaslValue) {
    match p {
        NaslValue::String(s) => {
            data.extend_from_slice(s.as_bytes());
        }
        NaslValue::Data(d) => data.extend_from_slice(d),
        NaslValue::Number(x) => {
            data.push(*x as u8);
        }
        NaslValue::Array(x) => {
            for v in x {
                append_nasl_value_as_u8(data, v)
            }
        }
        NaslValue::Dict(x) => {
            for v in x.values() {
                append_nasl_value_as_u8(data, v)
            }
        }
        NaslValue::Boolean(x) => match x {
            true => data.push(1),
            false => data.push(0),
        },
        NaslValue::AttackCategory(x) => data.push(*x as i32 as u8),
        _ => {}
    }
}

/// NASL function to parse numeric values into characters and combine with additional values
fn raw_string(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    let positional = resolve_positional_arguments(register);
    let mut data: Vec<u8> = vec![];
    for p in positional {
        append_nasl_value_as_u8(&mut data, &p);
    }
    Ok(data.into())
}

fn write_nasl_string(s: &mut String, value: &NaslValue) -> Result<(), FunctionError> {
    match value {
        NaslValue::String(x) => write!(s, "{x}"),
        NaslValue::Data(x) => {
            let x = x.iter().map(|x| *x as char).collect::<String>();
            write!(s, "{x}")
        }
        NaslValue::Number(x) => {
            let c = *x as u8 as char;
            if c.is_ascii_graphic() {
                write!(s, "{c}")
            } else {
                write!(s, ".")
            }
        }
        NaslValue::Array(x) => {
            for p in x {
                write_nasl_string(s, p)?;
            }
            Ok(())
        }
        NaslValue::Dict(x) => {
            for p in x.values() {
                write_nasl_string(s, p)?;
            }
            Ok(())
        }
        _ => write!(s, "."),
    }
    .map_err(|e| FunctionError::new("string", e.into()))
}

/// NASL function to parse values into string representations
fn string(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    let positional = resolve_positional_arguments(register);
    let mut s = String::with_capacity(2 * positional.len());
    for p in positional {
        write_nasl_string_value(&mut s, &p)?;
    }
    Ok(s.into())
}

fn write_nasl_string_value(s: &mut String, value: &NaslValue) -> Result<(), FunctionError> {
    match value {
        NaslValue::Array(x) => {
            for p in x {
                write_nasl_string(s, p)?;
            }
            Ok(())
        }
        NaslValue::Dict(x) => {
            for p in x.values() {
                write_nasl_string(s, p)?;
            }
            Ok(())
        }
        NaslValue::String(x) => write!(s, "{}", x),
        NaslValue::Number(x) => write!(s, "{}", x),
        NaslValue::Boolean(x) => write!(s, "{}", *x as i32),
        NaslValue::AttackCategory(x) => write!(s, "{}", *x as i32),
        _ => Ok(()),
    }
    .map_err(|e| FunctionError::new("string", e.into()))
}

/// NASL function to return uppercase equivalent of a given string
///
/// If this function retrieves anything but a string it returns NULL
fn toupper(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    let positional = resolve_positional_arguments(register);
    Ok(match positional.get(0) {
        Some(NaslValue::String(x)) => x.to_uppercase().into(),
        Some(NaslValue::Data(x)) => x
            .iter()
            .map(|x| *x as char)
            .collect::<String>()
            .to_uppercase()
            .into(),
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
        Some(NaslValue::Data(x)) => x
            .iter()
            .map(|x| *x as char)
            .collect::<String>()
            .to_lowercase()
            .into(),
        _ => NaslValue::Null,
    })
}

/// NASL function to return the length of string
///
/// If this function retrieves anything but a string it returns 0
fn strlen(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    let positional = resolve_positional_arguments(register);
    Ok(match positional.get(0) {
        Some(NaslValue::String(x)) => x.len().into(),
        Some(NaslValue::Data(x)) => x.len().into(),
        _ => 0_i64.into(),
    })
}

/// NASL function to return a substr of a string.
///
/// The first positional argument is the *string* to get the slice from.
/// As a second positional argument an *int* that contains the start index for the slice is required.
/// The optional third positional argument is an *int* and contains the end index for the slice.
/// If not given it is set to the end of the string.
/// If the start integer is higher than the value of the string NULL is returned.
fn substr(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    let positional = resolve_positional_arguments(register);
    if positional.len() < 2 {
        return Ok(NaslValue::Null);
    }
    // we checked previously if the size is sufficient
    unsafe {
        let s = positional.get_unchecked(0).to_string();
        let lidx: i64 = positional.get_unchecked(1).into();
        if lidx as usize > s.len() {
            return Ok(NaslValue::Null);
        }
        Ok(match positional.get(2) {
            Some(nv) => {
                let ridx: i64 = nv.into();
                (&s[lidx as usize..ridx as usize]).into()
            }
            _ => (&s[lidx as usize..]).into(),
        })
    }
}

/// NASL function to return a hex representation of a given positional string argument.
///
/// If the positional arguments are empty it returns NaslValue::Null.
/// It only uses the first positional argument and when it is not a NaslValue:String than it returns NaslValue::Null.
fn hexstr(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    let positional = resolve_positional_arguments(register);
    let hexler = |x: &str| -> Result<NaslValue, FunctionError> {
        let mut s = String::with_capacity(2 * x.len());
        for byte in x.as_bytes() {
            write!(s, "{byte:02X}").map_err(|e| FunctionError::new("hexstr", e.into()))?
        }
        Ok(s.into())
    };
    match positional.get(0) {
        Some(NaslValue::String(x)) => hexler(x),
        Some(NaslValue::Data(x)) => hexler(&x.iter().map(|x| *x as char).collect::<String>()),
        _ => Ok(NaslValue::Null),
    }
}

/// NASL function to return a buffer of required length with repeated occurrences of a specified string
///
/// Length argument is required and can be a named argument or a positional argument.
/// Data argument is an optional named argument and is taken to be "X" if not provided.
fn crap(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    let data = match register.named("data") {
        None => "X",
        Some(ContextType::Value(NaslValue::String(x))) => x,
        Some(x) => {
            let ek = match x {
                ContextType::Value(a) => ("data", "string", a).into(),
                ContextType::Function(_, _) => ("data", "string", "function").into(),
            };
            return Err(FunctionError::new("crap", ek));
        }
    };
    match register.named("length") {
        None => {
            let positional = resolve_positional_arguments(register);
            match positional.get(0) {
                Some(NaslValue::Number(x)) => Ok(NaslValue::String(data.repeat(*x as usize))),
                x => Err(FunctionError::new("crap", ("0", "numeric", x).into())),
            }
        }
        Some(ContextType::Value(NaslValue::Number(x))) => {
            Ok(NaslValue::String(data.repeat(*x as usize)))
        }
        x => Err(FunctionError::new("crap", ("length", "numeric", x).into())),
    }
}

/// NASL function to remove trailing whitespaces from a string
///
/// Takes one required positional argument of string type.
fn chomp(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    let positional = resolve_positional_arguments(register);
    match positional.get(0) {
        Some(NaslValue::String(x)) => Ok(x.trim_end().to_owned().into()),
        Some(NaslValue::Data(x)) => Ok(x
            .iter()
            .map(|x| *x as char)
            .collect::<String>()
            .trim_end()
            .to_owned()
            .into()),
        x => Err(FunctionError::new("chomp", ("0", "string", x).into())),
    }
}

/// NASL function to lookup position of a substring within a string
///
/// The first positional argument is the *string* to search through.
/// The second positional argument is the *string* to search for.
/// The optional third positional argument is an *int* containing an offset from where to start the search.
fn stridx(_: &str, _: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    let positional = resolve_positional_arguments(register);
    let haystack = match positional.get(0) {
        Some(NaslValue::String(x)) => x,
        x => return Err(FunctionError::new("stridx", ("0", "string", x).into())),
    };
    let needle = match positional.get(1) {
        Some(NaslValue::String(x)) => x,
        x => return Err(FunctionError::new("stridx", ("1", "string", x).into())),
    };
    let offset = match positional.get(2) {
        Some(NaslValue::Number(x)) => *x as usize,
        _ => 0_usize,
    };
    Ok(match &haystack[offset..].find(needle) {
        Some(index) => NaslValue::Number(*index as i64),
        None => NaslValue::Number(-1),
    })
}

/// NASL function to display any number of NASL values
///
/// Internally the string function is used to concatenate the given parameters
fn display(buf: &str, sink: &dyn Sink, register: &Register) -> Result<NaslValue, FunctionError> {
    register
        .logger()
        .print(string(buf, sink, register)?.to_string());
    Ok(NaslValue::Null)
}

/// Returns found function for key or None when not found
pub fn lookup(key: &str) -> Option<NaslFunction> {
    match key {
        "hexstr" => Some(hexstr),
        "raw_string" => Some(raw_string),
        "tolower" => Some(tolower),
        "toupper" => Some(toupper),
        "strlen" => Some(strlen),
        "string" => Some(string),
        "substr" => Some(substr),
        "crap" => Some(crap),
        "chomp" => Some(chomp),
        "stridx" => Some(stridx),
        "display" => Some(display),
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
        assert_eq!(parser.next(), Some(Ok(vec![123].into())));
        assert_eq!(parser.next(), Some(Ok(vec![123, 1].into())));
        assert_eq!(
            parser.next(),
            Some(Ok(vec![123, 1, 72, 97, 108, 108, 111].into()))
        );
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
    #[test]
    fn strlen() {
        let code = r###"
        strlen(0x7B);
        strlen('hallo');
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(parser.next(), Some(Ok(0i64.into())));
        assert_eq!(parser.next(), Some(Ok(5i64.into())));
    }
    #[test]
    fn string() {
        let code = r###"
        string(0x7B);
        string(0x7B, 1);
        string(0x7B, 1, "Hallo");
        string(0x7B, 1, NULL, "Hallo");
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(parser.next(), Some(Ok("123".into())));
        assert_eq!(parser.next(), Some(Ok("1231".into())));
        assert_eq!(parser.next(), Some(Ok("1231Hallo".into())));
        assert_eq!(parser.next(), Some(Ok("1231Hallo".into())));
    }

    #[test]
    fn substr() {
        let code = r###"
        substr("hello", 1);
        substr("hello", 0, 4);
        substr("hello", 6);
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(parser.next(), Some(Ok("ello".into())));
        assert_eq!(parser.next(), Some(Ok("hell".into())));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
    }

    #[test]
    fn crap() {
        let code = r###"
        crap(5);
        crap(length: 5);
        crap(data: "ab", length: 5);
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(parser.next(), Some(Ok("XXXXX".into())));
        assert_eq!(parser.next(), Some(Ok("XXXXX".into())));
        assert_eq!(parser.next(), Some(Ok("ababababab".into())));
    }

    #[test]
    fn chomp() {
        let code = r###"
        chomp("abc");
        chomp("abc\n");
        chomp("abc  ");
        chomp("abc\n\t\r ");
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(parser.next(), Some(Ok("abc".into())));
        assert_eq!(parser.next(), Some(Ok("abc".into())));
        assert_eq!(parser.next(), Some(Ok("abc".into())));
        assert_eq!(parser.next(), Some(Ok("abc".into())));
    }

    #[test]
    fn stridx() {
        let code = r###"
        stridx("abc", "bcd");
        stridx("abc", "bc");
        stridx("abc", "abc");
        stridx("blahabc", "abc", 4);
        stridx("blahabc", "abc", 3);
        stridx("blahbc", "abc", 2);
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(parser.next(), Some(Ok((-1_i64).into())));
        assert_eq!(parser.next(), Some(Ok(1_i64.into())));
        assert_eq!(parser.next(), Some(Ok(0_i64.into())));
        assert_eq!(parser.next(), Some(Ok(0_i64.into())));
        assert_eq!(parser.next(), Some(Ok(1_i64.into())));
        assert_eq!(parser.next(), Some(Ok((-1_i64).into())));
    }

    #[test]
    fn display() {
        let code = r###"
        display("abc");
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null)));
    }
}
