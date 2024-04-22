// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines NASL functions that deal with string and their helpers

use core::fmt::Write;
use nasl_builtin_utils::{
    resolve_positional_arguments, Context, ContextType, FunctionErrorKind, NaslFunction, Register,
};
use std::num::ParseIntError;

use nasl_syntax::NaslValue;

/// Decodes given string as hex and returns the result as a byte array
pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

/// Encodes given bytes to a hex string
pub fn encode_hex(bytes: &[u8]) -> Result<String, FunctionErrorKind> {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b)?;
    }
    Ok(s)
}

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
fn raw_string<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let positional = resolve_positional_arguments(register);
    let mut data: Vec<u8> = vec![];
    for p in positional {
        append_nasl_value_as_u8(&mut data, &p);
    }
    Ok(data.into())
}

fn write_nasl_string(s: &mut String, value: &NaslValue) -> Result<(), FunctionErrorKind> {
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
    .map_err(|e| e.into())
}

/// NASL function to parse values into string representations
fn string<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let positional = resolve_positional_arguments(register);
    let mut s = String::with_capacity(2 * positional.len());
    for p in positional {
        write_nasl_string_value(&mut s, &p)?;
    }
    Ok(s.into())
}

fn write_nasl_string_value(s: &mut String, value: &NaslValue) -> Result<(), FunctionErrorKind> {
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
        NaslValue::Data(x) => {
            let x = x.iter().map(|x| *x as char).collect::<String>();
            write!(s, "{}", x)
        }
        _ => Ok(()),
    }
    .map_err(|e| e.into())
}

/// NASL function to return uppercase equivalent of a given string
///
/// If this function retrieves anything but a string it returns NULL
fn toupper<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let positional = resolve_positional_arguments(register);
    Ok(match positional.first() {
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
fn tolower<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let positional = resolve_positional_arguments(register);
    Ok(match positional.first() {
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
fn strlen<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let positional = resolve_positional_arguments(register);
    Ok(match positional.first() {
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
fn substr<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
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
fn hexstr<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let positional = resolve_positional_arguments(register);
    let hexler = |x: &str| -> Result<NaslValue, FunctionErrorKind> {
        let mut s = String::with_capacity(2 * x.len());
        for byte in x.as_bytes() {
            write!(s, "{byte:02x}")?
        }
        Ok(s.into())
    };
    match positional.first() {
        Some(NaslValue::String(x)) => hexler(x),
        Some(NaslValue::Data(x)) => Ok(NaslValue::String(encode_hex(x)?.to_string())),
        _ => Ok(NaslValue::Null),
    }
}

/// NASL function to convert a hexadecimal representation into byte data.
///
/// The first positional argument must be a string, all other arguments are ignored. If either the no argument was given or the first positional is not a string, a error is returned.
fn hexstr_to_data<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    match resolve_positional_arguments(register).first() {
        Some(NaslValue::String(x)) => match decode_hex(x) {
            Ok(y) => Ok(NaslValue::Data(y)),
            Err(_) => Err((
                "first positional argument",
                "a string only containing 0-9a-fA-F of a even length",
                x.as_str(),
            )
                .into()),
        },
        Some(x) => Err((
            "first positional argument",
            "string",
            x.to_string().as_str(),
        )
            .into()),
        None => Err("0".into()),
    }
}

/// NASL function to convert byte data into hexadecimal representation as lower case string.
///
/// The first positional argument must be byte data, all other arguments are ignored. If either the no argument was given or the first positional is not byte data, a error is returned.
fn data_to_hexstr<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    match resolve_positional_arguments(register).first() {
        Some(NaslValue::Data(x)) => Ok(encode_hex(x)?.into()),
        Some(x) => Err(("first positional argument", "data", x.to_string().as_str()).into()),
        None => Err("0".into()),
    }
}

/// NASL function to return a buffer of required length with repeated occurrences of a specified string
///
/// Length argument is required and can be a named argument or a positional argument.
/// Data argument is an optional named argument and is taken to be "X" if not provided.
fn crap<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let data = match register.named("data") {
        None => "X",
        Some(ContextType::Value(NaslValue::String(x))) => x,
        Some(x) => {
            let ek = match x {
                ContextType::Value(a) => ("data", "string", a).into(),
                ContextType::Function(_, _) => ("data", "string", "function").into(),
            };
            return Err(ek);
        }
    };
    match register.named("length") {
        None => {
            let positional = resolve_positional_arguments(register);
            match positional.first() {
                Some(NaslValue::Number(x)) => Ok(NaslValue::String(data.repeat(*x as usize))),
                x => Err(("0", "numeric", x).into()),
            }
        }
        Some(ContextType::Value(NaslValue::Number(x))) => {
            Ok(NaslValue::String(data.repeat(*x as usize)))
        }
        x => Err(("length", "numeric", x).into()),
    }
}

/// NASL function to remove trailing whitespaces from a string
///
/// Takes one required positional argument of string type.
fn chomp<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let positional = resolve_positional_arguments(register);
    match positional.first() {
        Some(NaslValue::String(x)) => Ok(x.trim_end().to_owned().into()),
        Some(NaslValue::Data(x)) => Ok(x
            .iter()
            .map(|x| *x as char)
            .collect::<String>()
            .trim_end()
            .to_owned()
            .into()),
        x => Err(("0", "string", x).into()),
    }
}

/// NASL function to lookup position of a substring within a string
///
/// The first positional argument is the *string* to search through.
/// The second positional argument is the *string* to search for.
/// The optional third positional argument is an *int* containing an offset from where to start the search.
fn stridx<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let positional = resolve_positional_arguments(register);
    let haystack = match positional.first() {
        Some(NaslValue::String(x)) => x,
        x => return Err(("0", "string", x).into()),
    };
    let needle = match positional.get(1) {
        Some(NaslValue::String(x)) => x,
        x => return Err(("1", "string", x).into()),
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
fn display<K>(register: &Register, configs: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    println!("{}", &string(register, configs)?);
    Ok(NaslValue::Null)
}

/// Returns found function for key or None when not found
pub fn lookup<K>(key: &str) -> Option<NaslFunction<K>> {
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
        "hexstr_to_data" => Some(hexstr_to_data),
        "data_to_hexstr" => Some(data_to_hexstr),
        _ => None,
    }
}

/// The description builtin function
pub struct NaslString;

impl<K: AsRef<str>> nasl_builtin_utils::NaslFunctionExecuter<K> for NaslString {
    fn nasl_fn_execute(
        &self,
        name: &str,
        register: &Register,
        context: &Context<K>,
    ) -> Option<nasl_builtin_utils::NaslResult> {
        lookup(name).map(|x| x(register, context))
    }

    fn nasl_fn_defined(&self, name: &str) -> bool {
        lookup::<K>(name).is_some()
    }
}
