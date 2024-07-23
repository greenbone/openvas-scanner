// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines NASL functions that deal with string and their helpers

use core::fmt::Write;
use glob::{MatchOptions, Pattern};
use nasl_builtin_utils::{
    function::{FromNaslValue, Maybe},
    Context, FunctionErrorKind, NaslFunction, Register,
};
use nasl_function_proc_macro::nasl_function;
use std::num::ParseIntError;

use nasl_syntax::NaslValue;

/// `Some(string)` if constructed from either a `NaslValue::String`
/// or `NaslValue::Data`.
struct StringOrData(String);

impl<'a> FromNaslValue<'a> for StringOrData {
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FunctionErrorKind> {
        match value {
            NaslValue::String(string) => Ok(Self(string.clone())),
            NaslValue::Data(buffer) => {
                Ok(Self(buffer.iter().map(|x| *x as char).collect::<String>()))
            }
            _ => Err(FunctionErrorKind::WrongArgument(
                "Expected string or byte buffer.".to_string(),
            )),
        }
    }
}

/// Decodes given string as hex and returns the result as a byte array
pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

/// Encodes given bytes to a hex string
pub fn encode_hex(bytes: &[u8]) -> String {
    bytes
        .into_iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
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
#[nasl_function]
fn raw_string(positional: CheckedPositionals<&NaslValue>) -> Vec<u8> {
    let mut data: Vec<u8> = vec![];
    for p in positional.iter() {
        append_nasl_value_as_u8(&mut data, &p);
    }
    data
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
#[nasl_function]
fn string(positional: CheckedPositionals<&NaslValue>) -> Result<NaslValue, FunctionErrorKind> {
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
#[nasl_function]
fn toupper(s: Option<Maybe<StringOrData>>) -> Option<String> {
    s.map(Maybe::as_option)
        .flatten()
        .map(|inner| inner.0.to_uppercase())
}

/// NASL function to return lowercase equivalent of a given string
///
/// If this function retrieves anything but a string it returns NULL
#[nasl_function]
fn tolower(s: Option<Maybe<StringOrData>>) -> Option<String> {
    s.map(Maybe::as_option)
        .flatten()
        .map(|inner| inner.0.to_lowercase())
}

/// NASL function to return the length of string
///
/// If this function retrieves anything but a string it returns 0
#[nasl_function]
fn strlen(s: Option<Maybe<StringOrData>>) -> usize {
    s.map(Maybe::as_option)
        .flatten()
        .map(|inner| inner.0.len())
        .unwrap_or(0)
}

/// NASL function to return a substr of a string.
///
/// The first positional argument is the *string* to get the slice from.
/// As a second positional argument an *int* that contains the start index for the slice is required.
/// The optional third positional argument is an *int* and contains the end index for the slice.
/// If not given it is set to the end of the string.
/// If the start integer is higher than the value of the string NULL is returned.
#[nasl_function]
fn substr(s: StringOrData, start: usize, end: Option<usize>) -> Option<String> {
    if start > s.0.len() {
        None
    } else {
        Some(
            match end {
                Some(end) => &s.0[start..end],
                None => &s.0[start..],
            }
            .into(),
        )
    }
}

/// NASL function to return a hex representation of a given positional string argument.
///
/// If the positional arguments are empty it returns NaslValue::Null.
/// It only uses the first positional argument and when it is not a NaslValue:String than it returns NaslValue::Null.
#[nasl_function]
fn hexstr(s: Option<NaslValue>) -> Option<String> {
    match s? {
        NaslValue::String(s) => Some(encode_hex(s.as_bytes())),
        NaslValue::Data(bytes) => Some(encode_hex(&bytes)),
        _ => None,
    }
}

/// NASL function to convert an integer into a hexadecimal number.
/// This only works properly for numbers from 0 to 255, as it always
/// returns a string in the form 0x00.
#[nasl_function]
fn hex(s: i64) -> String {
    let wrapped = s.rem_euclid(256);
    format!("0x{:02x}", wrapped)
}

/// NASL function to convert a hexadecimal representation into byte data.
///
/// The first positional argument must be a string, all other arguments are ignored. If either the no argument was given or the first positional is not a string, a error is returned.
#[nasl_function]
fn hexstr_to_data(s: &str) -> Result<Vec<u8>, FunctionErrorKind> {
    decode_hex(s).map_err(|_| {
        FunctionErrorKind::WrongArgument(format!(
            "Expected an even-length string containing only 0-9a-fA-F, found '{}'",
            s
        ))
    })
}

/// NASL function to convert byte data into hexadecimal representation as lower case string.
///
/// The first positional argument must be byte data, all other arguments are ignored. If either the no argument was given or the first positional is not byte data, a error is returned.
#[nasl_function]
fn data_to_hexstr(bytes: Maybe<&[u8]>) -> Option<String> {
    bytes.map(encode_hex)
}

/// NASL function to return a buffer of required length with repeated occurrences of a specified string
///
/// Length argument is required and can be a named argument or a positional argument.
/// Data argument is an optional named argument and is taken to be "X" if not provided.
#[nasl_function(maybe_named(length), named(data))]
fn crap(length: usize, data: Option<&str>) -> String {
    let data = data.unwrap_or("X");
    data.repeat(length)
}

/// NASL function to remove trailing whitespaces from a string
///
/// Takes one required positional argument of string type.
#[nasl_function]
fn chomp(s: StringOrData) -> String {
    s.0.trim_end().into()
}

/// NASL function to lookup position of a substring within a string
///
/// The first positional argument is the *string* to search through.
/// The second positional argument is the *string* to search for.
/// The optional third positional argument is an *int* containing an offset from where to start the search.
#[nasl_function]
fn stridx(haystack: String, needle: String, offset: Option<usize>) -> i64 {
    let offset = offset.unwrap_or(0);
    match &haystack[offset..].find(&needle) {
        Some(index) => *index as i64,
        None => -1,
    }
}

/// NASL function to display any number of NASL values
///
/// Internally the string function is used to concatenate the given parameters
fn display(register: &Register, configs: &Context) -> Result<NaslValue, FunctionErrorKind> {
    println!("{}", &string(register, configs)?);
    Ok(NaslValue::Null)
}

/// NASL function that returns the ASCII code of the first character of a given string.
///
/// Takes a single positional argument.
#[nasl_function]
fn ord(s: &str) -> Option<u8> {
    s.chars().next().map(|c| c as u8)
}

/// NASL function that replaces a substring in one string with another string.
/// 1st positional argument: string in which the replacement takes place.
/// 2nd positional argument: string to replace the substring in the 1st argument with
/// 3rd positional argument: start index in the original string at which to perform the replacement
/// 4rd positional argument (optional): end index in the original string at which to perform the replacement.
#[nasl_function]
fn insstr(
    mut s: String,
    to_insert: &str,
    start: usize,
    end: Option<usize>,
) -> Result<String, FunctionErrorKind> {
    let end = end.unwrap_or(s.len()).min(s.len());
    if start > end {
        return Err(FunctionErrorKind::WrongArgument(format!(
            "start index ({}) larger than end ({}).",
            start, end
        )));
    }
    s.replace_range(start..end, to_insert);
    Ok(s)
}

/// Matches a string against a simple shell like pattern.
///
/// `string` is the string to be searched.
/// `pattern` contains the pattern to search for.
/// The optional argument `icase` toggles case sensitivity. Default: false (case sensitive). If true, search is case insensitive.
#[nasl_function(named(string), named(pattern), named(icase))]
fn match_(string: &str, pattern: &str, icase: Option<bool>) -> Result<bool, FunctionErrorKind> {
    let options = MatchOptions {
        case_sensitive: !icase.unwrap_or(false),
        require_literal_separator: false,
        require_literal_leading_dot: false,
    };
    Ok(Pattern::new(pattern)
        .map_err(|err| {
            FunctionErrorKind::WrongArgument(format!(
                "Argument 'pattern' to 'match' is not a valid pattern: {}. {}",
                pattern, err
            ))
        })?
        .matches_with(string, options))
}

/// Returns found function for key or None when not found
pub fn lookup(key: &str) -> Option<NaslFunction> {
    match key {
        "hexstr" => Some(hexstr),
        "hex" => Some(hex),
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
        "ord" => Some(ord),
        "match" => Some(match_),
        "insstr" => Some(insstr),
        _ => None,
    }
}

/// The description builtin function
pub struct NaslString;

impl nasl_builtin_utils::NaslFunctionExecuter for NaslString {
    fn nasl_fn_execute(
        &self,
        name: &str,
        register: &Register,
        context: &Context,
    ) -> Option<nasl_builtin_utils::NaslResult> {
        lookup(name).map(|x| x(register, context))
    }

    fn nasl_fn_defined(&self, name: &str) -> bool {
        lookup(name).is_some()
    }
}
