// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines NASL functions that deal with string and their helpers

#[cfg(test)]
mod tests;

use crate::nasl::{
    utils::{
        function::{bytes_to_str, CheckedPositionals, Maybe, StringOrData},
        FnError,
    },
    ArgumentError,
};
use core::fmt::Write;
use glob::{MatchOptions, Pattern};
use std::num::ParseIntError;
use thiserror::Error;

use crate::nasl::prelude::*;

use super::BuiltinError;

#[derive(Debug, Error)]
#[error("{0}")]
pub struct StringError(#[from] std::fmt::Error);

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
        .iter()
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
        append_nasl_value_as_u8(&mut data, p);
    }
    data
}

fn write_nasl_string(s: &mut String, value: &NaslValue) -> Result<(), StringError> {
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
fn string(positional: CheckedPositionals<&NaslValue>) -> Result<NaslValue, BuiltinError> {
    combine_positionals_to_string(positional)
}

fn combine_positionals_to_string(
    positional: CheckedPositionals<&NaslValue>,
) -> Result<NaslValue, BuiltinError> {
    let mut s = String::with_capacity(2 * positional.len());
    for p in positional {
        write_nasl_string_value(&mut s, p)?;
    }
    Ok(s.into())
}

fn write_nasl_string_value(s: &mut String, value: &NaslValue) -> Result<(), StringError> {
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
    s.and_then(Maybe::as_option)
        .map(|inner| inner.0.to_uppercase())
}

/// NASL function to return lowercase equivalent of a given string
///
/// If this function retrieves anything but a string it returns NULL
#[nasl_function]
fn tolower(s: Option<Maybe<StringOrData>>) -> Option<String> {
    s.and_then(Maybe::as_option)
        .map(|inner| inner.0.to_lowercase())
}

/// NASL function to return the length of string
///
/// If this function retrieves anything but a string it returns 0
#[nasl_function]
fn strlen(s: Option<Maybe<StringOrData>>) -> usize {
    s.and_then(Maybe::as_option)
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
fn hexstr_to_data(s: NaslValue) -> Result<Vec<u8>, ArgumentError> {
    let s = s.to_string();
    let s = s.as_str();
    decode_hex(s).map_err(|_| {
        ArgumentError::WrongArgument(format!(
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
fn crap(length: usize, data: Option<NaslValue>) -> String {
    let data = match data {
        Some(x) => x.to_string(),
        None => "X".to_string(),
    };

    data.as_str().repeat(length)
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
fn stridx(haystack: NaslValue, needle: NaslValue, offset: Option<usize>) -> i64 {
    let h = haystack.to_string();
    let haystack = h.as_str();
    let n = needle.to_string();
    let needle = n.as_str();

    let offset = offset.unwrap_or(0);
    match &haystack[offset..].find(needle) {
        Some(index) => *index as i64,
        None => -1,
    }
}

/// NASL function to display any number of NASL values
///
/// Internally the string function is used to concatenate the given parameters
#[nasl_function]
fn display(positional: CheckedPositionals<&NaslValue>) -> Result<NaslValue, BuiltinError> {
    println!("{}", &combine_positionals_to_string(positional)?);
    Ok(NaslValue::Null)
}

/// NASL function that returns the ASCII code of the first character of a given string.
///
/// Takes a single positional argument.
#[nasl_function]
fn ord(s: NaslValue) -> Option<u8> {
    let s = s.to_string();
    let s = s.as_str();
    s.chars().next().map(|c| c as u8)
}

/// NASL function to convert a string to an integer.  This function
/// tries to convert any given parameter into an integer. If the
/// conversion is not possible or no argument was given, a 0 is
/// returned instead. If a string contains any non-numerical
/// characters, it only converts, if the string starts with a
/// numerical character and end at the first appearance of any
/// non-numerical character. The TRUE value converts to 1, FALSE to 0.
#[nasl_function]
fn int(s: &NaslValue) -> i64 {
    match s {
        NaslValue::String(s) => str_to_int(s),
        NaslValue::Data(data) => str_to_int(&bytes_to_str(data)),
        NaslValue::Number(num) => *num,
        NaslValue::Boolean(b) => *b as i64,
        _ => 0,
    }
}

fn str_to_int(s: &str) -> i64 {
    s.parse::<i64>()
        .unwrap_or_else(|_| s[..s.len() - 1].parse::<i64>().unwrap_or(0))
}

/// NASL function that replaces a substring in one string with another string.
/// 1st positional argument: string in which the replacement takes place.
/// 2nd positional argument: string to replace the substring in the 1st argument with
/// 3rd positional argument: start index in the original string at which to perform the replacement
/// 4rd positional argument (optional): end index in the original string at which to perform the replacement.
#[nasl_function]
fn insstr(
    s: NaslValue,
    to_insert: NaslValue,
    start: usize,
    end: Option<usize>,
) -> Result<String, ArgumentError> {
    let mut s = s.to_string();

    let insb = to_insert.to_string();
    let ins = insb.as_str();

    let end = end.unwrap_or(s.len()).min(s.len());
    if start > end {
        return Err(ArgumentError::WrongArgument(format!(
            "start index ({}) larger than end ({}).",
            start, end
        )));
    }

    if s.len() >= (end + 1) {
        s.replace_range(start..(end + 1), ins);
    } else {
        s.replace_range(start..(end), ins);
    }

    Ok(s)
}

/// Matches a string against a simple shell like pattern.
///
/// `string` is the string to be searched.
/// `pattern` contains the pattern to search for.
/// The optional argument `icase` toggles case sensitivity. Default: false (case sensitive). If true, search is case insensitive.
#[nasl_function(named(string, pattern, icase))]
fn match_(string: NaslValue, pattern: NaslValue, icase: Option<bool>) -> Result<bool, FnError> {
    let options = MatchOptions {
        case_sensitive: !icase.unwrap_or(false),
        require_literal_separator: false,
        require_literal_leading_dot: false,
    };
    let strb = string.to_string();
    let string = strb.as_str();
    let pattb = pattern.to_string();
    let pattern = pattb.as_str();

    Ok(Pattern::new(pattern)
        .map_err(|err| {
            ArgumentError::WrongArgument(format!(
                "Argument 'pattern' to 'match' is not a valid pattern: {}. {}",
                pattern, err
            ))
        })?
        .matches_with(string, options))
}

/// This function splits a given NaslValue into parts, puts them into an array and returns it.
///
/// The first positional argument is the *string* to split.
///
/// The optional named argument *sep* is a NaslValue containing the
/// separator for splitting the string. The string is split after the
/// separator. By default the string is split at every line break.
///
/// The optional named argument *keep* is a *bool* and is used as flag
/// to enable/disable keeping the separator within the separated
/// string. By default *keep* is set to *TRUE*. *TRUE* means the
/// separator is kept, *FALSE* means the separator is discarded.
#[nasl_function(named(sep, keep))]
fn split(string: NaslValue, sep: Option<NaslValue>, keep: Option<bool>) -> Vec<String> {
    let strb = string.to_string();
    let str = strb.as_str();

    let separator: String;
    if let Some(s) = sep {
        separator = s.to_string();
    } else {
        separator = "\n".to_string();
    }

    let sep_aux = separator.as_str();

    if keep.unwrap_or(true) {
        str.split_inclusive(sep_aux).map(String::from).collect()
    } else {
        str.split(sep_aux).map(String::from).collect()
    }
}

/// This function looks up a substring within a string and replaces them with a given string.
/// The named argument string is the string to modify.
/// The named argument find is a string containing the substring to replace.
/// The optional named argument replace is a string containing the string to replace
/// `find` with. Assumed to be the empty string if not given.
/// The optional named argument count is an int. If specified, it
/// limits the number of replacements made to count. If left out
/// or set to 0, there is no limit on the number of replacements.
#[nasl_function(named(string, find, replace, count))]
fn str_replace(
    string: NaslValue,
    find: NaslValue,
    replace: Option<NaslValue>,
    count: Option<usize>,
) -> String {
    let strb = string.to_string();
    let string = strb.as_str();

    let findb = find.to_string();
    let find = findb.as_str();

    let rep: String;
    if let Some(r) = replace {
        rep = r.to_string();
    } else {
        rep = "".to_string();
    }

    match count {
        Some(count) if count > 0 => string.replacen(find, rep.as_str(), count),
        _ => string.replace(find, rep.as_str()),
    }
}

#[nasl_function]
/// This function finds the first occurrence of a substring within
/// a string and returns the rest of the string, starting at the substring
/// index.
///
/// 1st positional argument: string to search in.
/// 2nd positional argument: substring to search for.
fn strstr(string: NaslValue, find: NaslValue) -> NaslValue {
    let strb = string.to_string();
    let string = strb.as_str();

    let findb = find.to_string();
    let find = findb.as_str();

    if let Some(i) = string.find(find) {
        return NaslValue::String(string[i..].to_string());
    }
    NaslValue::Null
}
/// The description builtin function
pub struct NaslString;

function_set! {
    NaslString,
    (
        hexstr,
        hex,
        (raw_string, "raw_string"),
        (raw_string, "strcat"),
        tolower,
        toupper,
        strlen,
        string,
        substr,
        crap,
        chomp,
        stridx,
        display,
        hexstr_to_data,
        data_to_hexstr,
        ord,
        (match_, "match"),
        insstr,
        int,
        split,
        str_replace,
        strstr
    )
}
