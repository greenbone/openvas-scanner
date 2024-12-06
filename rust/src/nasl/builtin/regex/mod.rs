// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

#[cfg(test)]
mod tests;

use crate::nasl::prelude::*;
use regex::{Regex, RegexBuilder};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RegexError {
    #[error("Error building regular expression pattern: {0}")]
    BuildingError(regex::Error),
}

fn parse_search_string(mut s: &str, rnul: bool, multiline: bool) -> &str {
    if !rnul {
        s = s.split('\0').next().unwrap();
    }
    if !multiline {
        s = s.split('\n').next().unwrap();
    }

    s
}

fn make_regex(pattern: &str, icase: bool, multiline: bool) -> Result<Regex, RegexError> {
    match RegexBuilder::new(pattern.to_string().as_str())
        .case_insensitive(icase)
        .multi_line(multiline)
        .build()
    {
        Ok(re) => Ok(re),
        Err(e) => Err(RegexError::BuildingError(e)),
    }
}

/// Matches a string against a regular expression.
/// - string  String to search the pattern in
/// - pattern the pattern that should be matched
/// - icase   case insensitive flag
/// - rnul    replace the null char in the string. Default TRUE.
/// - multiline Is FALSE by default (string is truncated at the first
///                “end of line”), and can be set to TRUE for multiline search.
/// Return true if matches, false otherwise
#[nasl_function(named(string, pattern, icase, rnul, multiline))]
fn ereg(
    string: NaslValue,
    pattern: NaslValue,
    icase: Option<bool>,
    rnul: Option<bool>,
    multiline: Option<bool>,
) -> Result<bool, FnError> {
    let icase = icase.unwrap_or(false);
    let rnul = rnul.unwrap_or(true);
    let multiline = multiline.unwrap_or(false);

    let string = string.to_string();
    let string = parse_search_string(&string, rnul, multiline);

    let re = make_regex(&pattern.to_string(), icase, multiline)?;
    Ok(re.is_match(string))
}

/// Search for a pattern in a string and replace it.
/// - string  String to search the pattern in
/// - pattern pattern to search in the string for
/// - replace string to replace the pattern with
/// - icase   case insensitive flag
/// - rnul    replace the null char in the string. Default TRUE.
///
/// Return the new string with the pattern replaced with replace.
#[nasl_function(named(string, pattern, replace, icase, rnul))]
fn ereg_replace(
    string: NaslValue,
    pattern: NaslValue,
    replace: NaslValue,
    icase: Option<bool>,
    rnul: Option<bool>,
) -> Result<String, FnError> {
    let icase = icase.unwrap_or(false);
    let rnul = rnul.unwrap_or(true);

    let string = string.to_string();
    let string = parse_search_string(&string, rnul, true);
    let re = make_regex(&pattern.to_string(), icase, false)?;

    let out = re
        .replace_all(string, replace.to_string().as_str())
        .to_string();
    Ok(out)
}

/// Looks for a pattern in a string, line by line.
///
/// - string  String to search the pattern in
/// - pattern the pattern that should be matched
/// - icase   case insensitive flag
/// - rnul    replace the null char in the string. Default TRUE.
///
/// Returns the concatenation of all lines that match. Null otherwise.
#[nasl_function(named(string, pattern, icase, rnul))]
fn egrep(
    string: NaslValue,
    pattern: NaslValue,
    icase: Option<bool>,
    rnul: Option<bool>,
) -> Result<String, FnError> {
    let icase = icase.unwrap_or(false);
    let rnul = rnul.unwrap_or(true);

    let string = string.to_string();
    let string = parse_search_string(&string, rnul, true);
    let re = make_regex(&pattern.to_string(), icase, true)?;

    let lines: Vec<&str> = string
        .split_inclusive('\n')
        .filter(|l| re.is_match(l))
        .collect();

    Ok(lines.concat())
}

/// Does extended regular expression pattern matching.
///
/// - pattern An regex pattern
/// - string A string
/// - icase Boolean, for case sensitive
/// - find_all Boolean, to find all matches
/// - rnul replace the null char in the string. Default TRUE.
///
/// Return an array with the first match (find_all: False)
/// or an array with all matches (find_all: TRUE).
/// NULL or empty if no match was found.
#[nasl_function(named(string, pattern, find_all, icase, rnul))]
fn eregmatch(
    string: NaslValue,
    pattern: NaslValue,
    find_all: Option<bool>,
    icase: Option<bool>,
    rnul: Option<bool>,
) -> Result<NaslValue, FnError> {
    let icase = icase.unwrap_or(false);
    let rnul = rnul.unwrap_or(true);
    let find_all = find_all.unwrap_or(false);

    let string = string.to_string();
    let string = parse_search_string(&string, rnul, true);
    let re = make_regex(&pattern.to_string(), icase, true)?;

    let matches = match find_all {
        true => re
            .find_iter(string)
            .map(|m| NaslValue::String(m.as_str().to_string()))
            .collect(),
        false => match re.find(string) {
            Some(s) => vec![NaslValue::String(s.as_str().to_string())],
            None => vec![],
        },
    };

    Ok(NaslValue::Array(matches))
}

pub struct RegularExpressions;

function_set! {
    RegularExpressions,
    (
        ereg,
        egrep,
        ereg_replace,
        eregmatch
    )
}
