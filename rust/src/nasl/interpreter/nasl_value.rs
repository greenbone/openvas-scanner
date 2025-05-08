// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::ops::{BitAnd, BitOr, BitXor, Div, Mul, Rem, Shl, Shr};
use std::{cmp::Ordering, collections::HashMap, fmt::Display};

use regex::Regex;

use crate::nasl::syntax::grammar::{Block, Statement};
use crate::nasl::utils::function::bytes_to_str;
use crate::{
    nasl::interpreter::{InterpretError, InterpretErrorKind},
    storage::items::{kb::KbItem, nvt::ACT},
};

#[derive(Clone, Debug)]
pub enum ContextType {
    /// Represents a function definition
    Function(Vec<String>, Block<Statement>),
    /// Represents a variable
    Value(NaslValue),
}

/// Represents a NASL value during runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
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

    pub(crate) fn convert_to_number(&self) -> i64 {
        match self {
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

    pub(crate) fn as_string(&self) -> Result<String, InterpretErrorKind> {
        match self {
            NaslValue::String(string) => Ok(string.clone()),
            NaslValue::Data(buffer) => Ok(bytes_to_str(buffer)),
            _ => Err(InterpretErrorKind::ExpectedString),
        }
    }

    pub(crate) fn convert_to_boolean(&self) -> bool {
        match self {
            NaslValue::Boolean(b) => *b,
            NaslValue::Number(n) => *n != 0,
            NaslValue::String(s) => !s.is_empty() && s != "0",
            NaslValue::Data(d) => !d.is_empty(),
            NaslValue::Array(v) => !v.is_empty(),
            NaslValue::Null => false,
            _ => true,
        }
    }

    pub(crate) fn as_dict(&self) -> Result<&HashMap<String, NaslValue>, InterpretErrorKind> {
        match self {
            NaslValue::Dict(d) => Ok(d),
            _ => Err(InterpretErrorKind::ExpectedDict),
        }
    }

    pub(crate) fn as_array(&self) -> Result<&Vec<NaslValue>, InterpretErrorKind> {
        match self {
            NaslValue::Array(d) => Ok(d),
            _ => Err(InterpretErrorKind::ExpectedArray),
        }
    }

    pub(crate) fn as_dict_mut(
        &mut self,
    ) -> Result<&mut HashMap<String, NaslValue>, InterpretErrorKind> {
        match self {
            NaslValue::Dict(d) => Ok(d),
            _ => Err(InterpretErrorKind::ExpectedDict),
        }
    }

    pub(crate) fn as_array_mut(&mut self) -> Result<&mut Vec<NaslValue>, InterpretErrorKind> {
        match self {
            NaslValue::Array(d) => Ok(d),
            _ => Err(InterpretErrorKind::ExpectedArray),
        }
    }

    #[must_use]
    pub fn is_dict(&self) -> bool {
        matches!(self, Self::Dict(..))
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

    pub(crate) fn index(&self, index: NaslValue) -> Result<&NaslValue, InterpretError> {
        if let Ok(arr) = self.as_array() {
            let index = index.as_number()?;
            let index = index
                .try_into()
                .map_err(|_| InterpretErrorKind::NegativeIndex(index))?;
            arr.get(index)
                .ok_or_else(|| InterpretErrorKind::ArrayOutOfRange(index).into())
        } else if let Ok(dict) = self.as_dict() {
            let index = index.as_string()?;
            dict.get(&index)
                .ok_or_else(|| InterpretErrorKind::DictKeyDoesNotExist(index).into())
        } else {
            Err(InterpretErrorKind::ArrayOrDictExpected.into())
        }
    }

    pub(crate) fn add(&self, rhs: NaslValue) -> NaslValue {
        self.add_string(&rhs)
            .unwrap_or_else(|| (self.convert_to_number() + rhs.convert_to_number()).into())
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
            .unwrap_or_else(|| (self.convert_to_number() - rhs.convert_to_number()).into())
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
        Ok(NaslValue::Boolean(!self.convert_to_boolean()))
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
                write!(f, "{}", *category)
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
                let b1 = self.convert_to_boolean();
                let b2 = rhs.convert_to_boolean();
                Ok($path(b1 $op b2))
            }
        }
    };
}

impl_boolean_operator!(and, Self::Boolean, &&);
impl_boolean_operator!(or, Self::Boolean, ||);

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

impl ContextType {
    pub(crate) fn as_value(&self) -> Result<&NaslValue, InterpretErrorKind> {
        if let Self::Value(val) = self {
            Ok(val)
        } else {
            Err(InterpretErrorKind::FunctionExpectedValue)
        }
    }

    pub(crate) fn as_value_mut(&mut self) -> Result<&mut NaslValue, InterpretErrorKind> {
        if let Self::Value(val) = self {
            Ok(val)
        } else {
            Err(InterpretErrorKind::FunctionExpectedValue)
        }
    }
}

impl std::fmt::Display for ContextType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContextType::Function(_, _) => write!(f, ""),
            ContextType::Value(v) => write!(f, "{v}"),
        }
    }
}
