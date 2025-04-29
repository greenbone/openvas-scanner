// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::ops::{BitAnd, BitOr, BitXor, Div, Mul, Rem, Shl, Shr};
use std::{cmp::Ordering, collections::HashMap, fmt::Display};

use regex::Regex;

use crate::nasl::utils::function::bytes_to_str;
use crate::{
    nasl::interpreter::{InterpretError, InterpretErrorKind},
    storage::items::{kb::KbItem, nvt::ACT},
};

use super::{Keyword, token::Literal};

/// Represents a valid Value of NASL
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub enum NaslValue {
    /// String value
    String(String),
    /// Data value
    Data(Vec<u8>),
    /// Number value
    Number(i64),
    /// Array value
    Array(Vec<NaslValue>),
    /// Array value
    Dict(HashMap<String, NaslValue>),
    /// Boolean value
    Boolean(bool),
    /// Attack category keyword
    AttackCategory(ACT),
    /// Null value
    #[default]
    Null,
    /// Returns value of the context
    Return(Box<NaslValue>),
    /// Creates n runs for each entry
    ///
    /// If the value is more than one element the interpreter creates n - 1 shadow clones from
    /// itself and will execute each following statement based on each stored instance. This needs
    /// to be done for downwards compatible reasons. Within `openvas` `get_kb_item` does create for
    /// each item within found key when it is a list a fork to allow scripts like:
    /// ```text
    /// set_kb_item(name: "test", value: 1);
    /// set_kb_item(name: "test", value: 2);
    /// set_kb_item(name: "test", value: 3);
    /// set_kb_item(name: "test", value: 4);
    /// set_kb_item(name: "test", value: 5);
    /// display(get_kb_item("test"));
    /// ```
    /// to print each kb_item within test.
    Fork(Vec<NaslValue>),
    /// Signals continuing a loop
    Continue,
    /// Signals a break of a control structure
    Break,
    /// Exit value of the script
    Exit(i64),
}

impl NaslValue {
    /// Transform NASLValue to storage::types::Primitive
    pub fn as_kb(self) -> KbItem {
        use KbItem::*;
        match self {
            Self::String(s) => String(s),
            Self::Data(x) => Data(x),
            Self::Number(x) => Number(x),
            Self::Array(x) => Array(x.into_iter().map(|x| x.as_kb()).collect()),
            Self::Dict(x) => Dict(x.into_iter().map(|(k, v)| (k, v.as_kb())).collect()),
            Self::Boolean(x) => Boolean(x),
            _ => Null,
        }
    }

    pub(crate) fn as_number(&self) -> Result<i64, InterpretErrorKind> {
        match self {
            NaslValue::Number(n) => Ok(*n),
            _ => Err(InterpretErrorKind::ExpectedNumber),
        }
    }

    pub(crate) fn as_string(&self) -> Result<String, InterpretErrorKind> {
        match self {
            NaslValue::String(string) => Ok(string.clone()),
            NaslValue::Data(buffer) => Ok(bytes_to_str(buffer)),
            _ => Err(InterpretErrorKind::ExpectedString),
        }
    }

    pub(crate) fn as_boolean(&self) -> Result<bool, InterpretErrorKind> {
        match self {
            NaslValue::Boolean(b) => Ok(*b),
            NaslValue::Number(n) => Ok(*n != 0),
            NaslValue::String(s) => Ok(!s.is_empty()),
            NaslValue::Data(d) => Ok(!d.is_empty()),
            NaslValue::Array(_) => Ok(true),
            _ => Ok(true),
        }
    }

    fn add_string(&self, rhs: &NaslValue) -> Option<NaslValue> {
        let concatenated = || format!("{self}{rhs}");
        match self {
            NaslValue::String(_) => return Some(NaslValue::String(concatenated())),
            NaslValue::Data(_) => return Some(NaslValue::Data(concatenated().into())),
            _ => {}
        }
        match rhs {
            NaslValue::String(_) => Some(NaslValue::String(concatenated())),
            NaslValue::Data(_) => Some(NaslValue::Data(concatenated().into())),
            _ => None,
        }
    }

    pub(crate) fn add(&self, rhs: NaslValue) -> NaslValue {
        self.add_string(&rhs)
            .unwrap_or_else(|| (i64::from(self) + i64::from(rhs)).into())
    }

    fn sub_string(&self, rhs: &NaslValue) -> Option<NaslValue> {
        let concatenated = || {
            let lhs = self.to_string();
            let rhs = rhs.to_string();
            lhs.replacen(&rhs, "", 1)
        };
        match self {
            NaslValue::String(_) => return Some(NaslValue::String(concatenated())),
            NaslValue::Data(_) => return Some(NaslValue::Data(concatenated().into())),
            _ => {}
        }
        match rhs {
            NaslValue::String(_) => Some(NaslValue::String(concatenated())),
            NaslValue::Data(_) => Some(NaslValue::Data(concatenated().into())),
            _ => None,
        }
    }

    pub(crate) fn sub(&self, rhs: NaslValue) -> NaslValue {
        self.sub_string(&rhs)
            .unwrap_or_else(|| (i64::from(self) - i64::from(rhs)).into())
    }

    pub(crate) fn shr_unsigned(&self, rhs: NaslValue) -> Result<NaslValue, InterpretError> {
        let lhs = self.as_number()?;
        let rhs = rhs.as_number()?;
        let result = ((lhs as u32) >> rhs) as i32;
        Ok(NaslValue::Number(result as i64))
    }

    pub(crate) fn neg(&self) -> Result<NaslValue, InterpretError> {
        Ok(NaslValue::Number(-self.as_number()?))
    }

    pub(crate) fn not(&self) -> Result<NaslValue, InterpretError> {
        Ok(NaslValue::Boolean(!self.as_boolean()?))
    }

    pub(crate) fn bitwise_not(&self) -> Result<NaslValue, InterpretError> {
        Ok(NaslValue::Number(!self.as_number()?))
    }

    pub(crate) fn pow(&self, rhs: NaslValue) -> Result<NaslValue, InterpretError> {
        let lhs = self.as_number()?;
        let rhs = rhs.as_number()?;
        Ok(NaslValue::Number((lhs as u32).pow(rhs as u32) as i64))
    }

    pub(crate) fn match_regex(&self, matches: NaslValue) -> Result<NaslValue, InterpretError> {
        let matches = matches.as_string()?;
        match Regex::new(&matches) {
            Ok(c) => Ok(NaslValue::Boolean(c.is_match(&self.to_string()))),
            Err(_) => Err(InterpretError::unparse_regex(&matches)),
        }
    }

    pub(crate) fn match_string(&self, matches: NaslValue) -> Result<NaslValue, InterpretError> {
        let matches = matches.as_string()?;
        Ok(NaslValue::Boolean(self.as_string()?.contains(&matches)))
    }
}

impl PartialOrd for NaslValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NaslValue {
    fn cmp(&self, other: &Self) -> Ordering {
        let a: Vec<u8> = self.into();
        let b: Vec<u8> = other.into();
        a.cmp(&b)
    }
}

impl Display for NaslValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NaslValue::String(x) => write!(f, "{x}"),
            NaslValue::Number(x) => write!(f, "{x}"),
            NaslValue::Array(x) => write!(
                f,
                "{}",
                x.iter()
                    .enumerate()
                    .map(|(i, v)| format!("{}: {}", i, v))
                    .collect::<Vec<String>>()
                    .join(",")
            ),
            NaslValue::Data(x) => write!(f, "{}", x.iter().map(|x| *x as char).collect::<String>()),
            NaslValue::Dict(x) => write!(
                f,
                "{}",
                x.iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect::<Vec<String>>()
                    .join(",")
            ),
            NaslValue::Boolean(true) => write!(f, "1"),
            NaslValue::Boolean(false) => write!(f, "0"),
            NaslValue::Null => write!(f, "\0"),
            NaslValue::Exit(rc) => write!(f, "exit({})", rc),
            NaslValue::AttackCategory(category) => {
                write!(f, "{}", Keyword::ACT(*category))
            }
            NaslValue::Return(rc) => write!(f, "return({:?})", *rc),
            NaslValue::Continue => write!(f, "continue"),
            NaslValue::Break => write!(f, "break"),
            NaslValue::Fork(x) => write!(
                f,
                "Fork[{}]",
                x.iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<String>>()
                    .join(",")
            ),
        }
    }
}

impl From<&[u8]> for NaslValue {
    fn from(value: &[u8]) -> Self {
        value.to_vec().into()
    }
}

impl From<Vec<u8>> for NaslValue {
    fn from(s: Vec<u8>) -> Self {
        Self::Data(s)
    }
}

impl From<bool> for NaslValue {
    fn from(b: bool) -> Self {
        NaslValue::Boolean(b)
    }
}

impl From<&str> for NaslValue {
    fn from(s: &str) -> Self {
        Self::String(s.to_owned())
    }
}

impl From<String> for NaslValue {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<i32> for NaslValue {
    fn from(n: i32) -> Self {
        Self::Number(n as i64)
    }
}

impl From<i64> for NaslValue {
    fn from(n: i64) -> Self {
        Self::Number(n)
    }
}

impl From<usize> for NaslValue {
    fn from(n: usize) -> Self {
        Self::Number(n as i64)
    }
}

impl From<HashMap<String, NaslValue>> for NaslValue {
    fn from(x: HashMap<String, NaslValue>) -> Self {
        NaslValue::Dict(x)
    }
}

macro_rules! impl_number_operator {
    ($ident: ident, $path: expr) => {
        impl NaslValue {
            pub fn $ident(&self, rhs: NaslValue) -> Result<NaslValue, InterpretError> {
                let n1 = self.as_number()?;
                let n2 = rhs.as_number()?;
                Ok($path(n1.$ident(&n2)))
            }
        }
    };
}

impl_number_operator!(mul, Self::Number);
impl_number_operator!(div, Self::Number);
impl_number_operator!(rem, Self::Number);
impl_number_operator!(shl, Self::Number);
impl_number_operator!(shr, Self::Number);
impl_number_operator!(bitor, Self::Number);
impl_number_operator!(bitand, Self::Number);
impl_number_operator!(bitxor, Self::Number);
impl_number_operator!(eq, Self::Boolean);
impl_number_operator!(ne, Self::Boolean);
impl_number_operator!(gt, Self::Boolean);
impl_number_operator!(ge, Self::Boolean);
impl_number_operator!(lt, Self::Boolean);
impl_number_operator!(le, Self::Boolean);

macro_rules! impl_boolean_operator {
    ($ident: ident, $path: expr, $op: tt) => {
        impl NaslValue {
            pub fn $ident(&self, rhs: NaslValue) -> Result<NaslValue, InterpretError> {
                let b1 = self.as_boolean()?;
                let b2 = rhs.as_boolean()?;
                Ok($path(b1 $op b2))
            }
        }
    };
}

impl_boolean_operator!(and, Self::Boolean, &&);
impl_boolean_operator!(or, Self::Boolean, ||);

// TODO turn these into error-based conversions

impl From<NaslValue> for Vec<u8> {
    fn from(value: NaslValue) -> Self {
        match value {
            NaslValue::String(x) => x.into(),
            NaslValue::Data(x) => x,
            NaslValue::Array(x) => x
                .iter()
                .flat_map(<&NaslValue as Into<Vec<u8>>>::into)
                .collect(),
            NaslValue::Boolean(_) | NaslValue::Number(_) | NaslValue::Dict(_) => {
                value.to_string().as_bytes().into()
            }
            NaslValue::AttackCategory(_)
            | NaslValue::Fork(_)
            | NaslValue::Null
            | NaslValue::Return(_)
            | NaslValue::Continue
            | NaslValue::Break
            | NaslValue::Exit(_) => vec![],
        }
    }
}

impl From<NaslValue> for bool {
    fn from(value: NaslValue) -> Self {
        match value {
            NaslValue::String(string) => !string.is_empty() && string != "0",
            NaslValue::Array(v) => !v.is_empty(),
            NaslValue::Data(v) => !v.is_empty(),
            NaslValue::Boolean(boolean) => boolean,
            NaslValue::Null => false,
            NaslValue::Number(number) => number != 0,
            NaslValue::Exit(number) => number != 0,
            NaslValue::AttackCategory(_) => true,
            NaslValue::Dict(v) => !v.is_empty(),
            NaslValue::Return(_) => true,
            NaslValue::Continue => false,
            NaslValue::Break => false,
            NaslValue::Fork(v) => v.is_empty(),
        }
    }
}

impl From<&NaslValue> for i64 {
    fn from(value: &NaslValue) -> Self {
        match value {
            NaslValue::String(_) => 1,
            &NaslValue::Number(x) => x,
            NaslValue::Array(_) => 1,
            NaslValue::Data(_) => 1,
            NaslValue::Dict(_) => 1,
            &NaslValue::Boolean(x) => x as i64,
            &NaslValue::AttackCategory(x) => x as i64,
            NaslValue::Null => 0,
            &NaslValue::Exit(x) => x,
            &NaslValue::Return(_) => -1,
            &NaslValue::Continue => 0,
            &NaslValue::Break => 0,
            NaslValue::Fork(_) => 1,
        }
    }
}

impl From<&NaslValue> for Vec<u8> {
    fn from(value: &NaslValue) -> Vec<u8> {
        match value {
            NaslValue::String(x) => x.as_bytes().to_vec(),
            &NaslValue::Number(x) => x.to_ne_bytes().to_vec(),
            NaslValue::Data(x) => x.to_vec(),
            _ => Vec::new(),
        }
    }
}

impl From<NaslValue> for i64 {
    fn from(nv: NaslValue) -> Self {
        i64::from(&nv)
    }
}

impl From<&Literal> for NaslValue {
    fn from(val: &Literal) -> Self {
        match val {
            Literal::String(s) => NaslValue::String(s.clone()),
            Literal::Data(data) => NaslValue::Data(data.clone()),
            Literal::Number(num) => NaslValue::Number(*num),
            Literal::IPv4Address(ipv4_addr) => NaslValue::String(ipv4_addr.to_string()),
            Literal::Null => NaslValue::Null,
            Literal::Boolean(b) => NaslValue::Boolean(*b),
        }
    }
}

// is used for loops, maybe refactor
impl From<NaslValue> for Vec<NaslValue> {
    fn from(value: NaslValue) -> Self {
        match value {
            NaslValue::Array(ret) => ret,
            NaslValue::Dict(ret) => ret.values().cloned().collect(),
            NaslValue::Boolean(_) | NaslValue::Number(_) => vec![value],
            NaslValue::Data(ret) => ret.into_iter().map(|x| NaslValue::Data(vec![x])).collect(),
            NaslValue::String(ret) => ret
                .chars()
                .map(|x| NaslValue::String(x.to_string()))
                .collect(),
            _ => vec![],
        }
    }
}

impl From<KbItem> for NaslValue {
    fn from(value: KbItem) -> Self {
        use KbItem::*;
        match value {
            String(x) => Self::String(x),
            Data(x) => Self::Data(x),
            Number(x) => Self::Number(x),
            Array(x) => Self::Array(x.into_iter().map(Self::from).collect()),
            Dict(x) => Self::Dict(x.into_iter().map(|(k, v)| (k, Self::from(v))).collect()),
            Boolean(x) => Self::Boolean(x),
            Null => Self::Null,
        }
    }
}
