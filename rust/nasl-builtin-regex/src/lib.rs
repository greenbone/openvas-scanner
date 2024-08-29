// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use nasl_builtin_utils::{error::FunctionErrorKind, NaslFunction};
use nasl_builtin_utils::{Context, Register};
use nasl_function_proc_macro::nasl_function;
use nasl_syntax::NaslValue;
use regex::RegexBuilder;

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
) -> Result<NaslValue, FunctionErrorKind> {
    let icase = icase.unwrap_or_default();
    let rnul = rnul.unwrap_or(true);
    let multiline = multiline.unwrap_or_default();

    let str_bind = string.to_string();
    let mut str_aux = str_bind.as_str();

    if !rnul {
        let s = match str_aux.chars().position(|c| c == '\0') {
            Some(i) => i,
            None => str_aux.len(),
        };
        (str_aux, _) = str_aux.split_at(s);
    }

    if !multiline {
        let s = match str_aux.chars().position(|c| c == '\n') {
            Some(i) => i,
            None => str_aux.len(),
        };
        (str_aux, _) = str_aux.split_at(s);
    }

    let re = match RegexBuilder::new(pattern.to_string().as_str())
        .case_insensitive(icase)
        .multi_line(multiline)
        .build()
    {
        Ok(re) => re,
        Err(e) => {
            return Err(FunctionErrorKind::Dirty(format!(
                " Error building regular expression pattern: {}",
                e
            )));
        }
    };

    Ok(NaslValue::Boolean(re.is_match(str_aux)))
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
) -> Result<NaslValue, FunctionErrorKind> {
    let icase = icase.unwrap_or_default();
    let rnul = rnul.unwrap_or(true);

    let str_bind = string.to_string();
    let mut str_aux = str_bind.as_str();

    if !rnul {
        let s = match str_aux.chars().position(|c| c == '\0') {
            Some(i) => i,
            None => str_aux.len(),
        };
        (str_aux, _) = str_aux.split_at(s);
    }

    let re = match RegexBuilder::new(pattern.to_string().as_str())
        .case_insensitive(icase)
        .build()
    {
        Ok(re) => re,
        Err(e) => {
            return Err(FunctionErrorKind::Dirty(format!(
                " Error building regular expression pattern: {}",
                e
            )));
        }
    };

    let out = re
        .replace_all(str_aux, replace.to_string().as_str())
        .to_string();
    Ok(NaslValue::String(out))
}

/// Looks for a pattern in a string, line by line.
///
/// - string  String to search the pattern in
/// - pattern the pattern that should be matched
/// - icase   case insensitive flag
/// - rnul    replace the null char in the string. Default TRUE.
///
/// Returns the concatenation of all lines that match. Null otherwise.
#[nasl_function(named(string, pattern, replace, icase, rnul))]
fn egrep(
    string: NaslValue,
    pattern: NaslValue,
    icase: Option<bool>,
    rnul: Option<bool>,
) -> Result<NaslValue, FunctionErrorKind> {
    let icase = icase.unwrap_or_default();
    let rnul = rnul.unwrap_or(true);

    let str_bind = string.to_string();
    let mut str_aux = str_bind.as_str();

    if !rnul {
        let s = match str_aux.chars().position(|c| c == '\0') {
            Some(i) => i,
            None => str_aux.len(),
        };
        (str_aux, _) = str_aux.split_at(s);
    }

    let re = match RegexBuilder::new(pattern.to_string().as_str())
        .case_insensitive(icase)
        .multi_line(true)
        .build()
    {
        Ok(re) => re,
        Err(e) => {
            return Err(FunctionErrorKind::Dirty(format!(
                " Error building regular expression pattern: {}",
                e
            )));
        }
    };

    let lines: Vec<&str> = str_aux
        .split_inclusive('\n')
        .filter(|l| re.is_match(l))
        .collect();

    Ok(NaslValue::String(lines.concat()))
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
) -> Result<NaslValue, FunctionErrorKind> {
    let icase = icase.unwrap_or_default();
    let rnul = rnul.unwrap_or(true);

    let find_all = find_all.unwrap_or_default();
    let str_bind = string.to_string();

    let mut str_aux = str_bind.as_str();

    if !rnul {
        let s = match str_aux.chars().position(|c| c == '\0') {
            Some(i) => i,
            None => str_aux.len(),
        };
        (str_aux, _) = str_aux.split_at(s);
    }

    let re = match RegexBuilder::new(pattern.to_string().as_str())
        .case_insensitive(icase)
        .multi_line(true)
        .build()
    {
        Ok(re) => re,
        Err(e) => {
            return Err(FunctionErrorKind::Dirty(format!(
                " Error building regular expression pattern: {}",
                e
            )));
        }
    };

    let matches = match find_all {
        true => re
            .find_iter(str_aux)
            .map(|m| NaslValue::String(m.as_str().to_string()))
            .collect(),
        false => match re.find(str_aux) {
            Some(s) => vec![NaslValue::String(s.as_str().to_string())],
            None => vec![],
        },
    };

    Ok(NaslValue::Array(matches))
}

/// Returns found function for key or None when not found
pub fn lookup(key: &str) -> Option<NaslFunction> {
    match key {
        "ereg" => Some(ereg),
        "egrep" => Some(egrep),
        "ereg_replace" => Some(ereg_replace),
        "eregmatch" => Some(eregmatch),
        _ => None,
    }
}

pub struct RegularExpressions;

impl nasl_builtin_utils::NaslFunctionExecuter for RegularExpressions {
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
