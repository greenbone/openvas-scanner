// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{cmp::Ordering, collections::HashMap, fmt::Display};

use crate::{IdentifierType, Token, TokenCategory, ACT};

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
    pub fn as_primitive(self) -> storage::types::Primitive {
        use storage::types::Primitive::*;
        match self {
            Self::String(s) => String(s),
            Self::Data(x) => Data(x),
            Self::Number(x) => Number(x),
            Self::Array(x) => Array(x.into_iter().map(|x| x.as_primitive()).collect()),
            Self::Dict(x) => Dict(x.into_iter().map(|(k, v)| (k, v.as_primitive())).collect()),
            Self::Boolean(x) => Boolean(x),
            _ => Null,
        }
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
                write!(f, "{}", IdentifierType::ACT(*category))
            }
            NaslValue::Return(rc) => write!(f, "return({:?})", *rc),
            NaslValue::Continue => write!(f, "continue"),
            NaslValue::Break => write!(f, "break"),
            NaslValue::Fork(x) => write!(
                f,
                "Creates {} runs, for {}",
                x.len(),
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

impl TryFrom<&Token> for NaslValue {
    type Error = TokenCategory;

    fn try_from(token: &Token) -> Result<Self, Self::Error> {
        match token.category() {
            TokenCategory::String(category) | TokenCategory::IPv4Address(category) => {
                Ok(NaslValue::String(category.clone()))
            }
            TokenCategory::Data(data) => Ok(NaslValue::Data(data.clone())),
            TokenCategory::Identifier(IdentifierType::Undefined(id)) => {
                Ok(NaslValue::String(id.clone()))
            }
            TokenCategory::Number(num) => Ok(NaslValue::Number(*num)),
            TokenCategory::Identifier(IdentifierType::Null) => Ok(NaslValue::Null),
            TokenCategory::Identifier(IdentifierType::True) => Ok(NaslValue::Boolean(true)),
            TokenCategory::Identifier(IdentifierType::False) => Ok(NaslValue::Boolean(false)),
            o => Err(o.clone()),
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

impl From<storage::types::Primitive> for NaslValue {
    fn from(value: storage::types::Primitive) -> Self {
        use storage::types::Primitive::*;
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
