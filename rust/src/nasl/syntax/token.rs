// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! This module defines the TokenTypes as well as Token and extends Cursor with advance_token
use std::fmt::Display;

#[cfg(test)]
use serde::{Deserialize, Serialize};

use crate::{nasl::interpreter::InterpretError, storage::item::ACT};

use super::tokenizer::NumberBase;

/// Is used to identify which token type is unclosed
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(Serialize, Deserialize))]
pub enum UnclosedTokenKind {
    String,
    Data,
}

macro_rules! make_keyword_matcher {
    ($($matcher:ident : $define:expr),+) => {

impl IdentifierType {
    /// Creates a new keyword based on a string identifier
    pub fn new(keyword: &str) -> Self {
        match keyword {
           $(
           stringify!($matcher) => $define,
           )*
            _ => Self::Undefined(keyword.to_owned())
        }

    }

    /// Returns the length of the identifier
    pub fn len(&self) -> usize {
        $(
        if self == &$define {
            return stringify!($matcher).len();
        }
        )*
        if let IdentifierType::Undefined(r) = self {
            return r.len();
        } else {
            return 0;
        }
    }

    /// Returns true when len == 0
    pub fn is_empty(&self) -> bool {
         self.len() == 0
    }

}
impl Display for IdentifierType {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        $(
        if self == &$define {
            return write!(f, stringify!($matcher));
        }
        )*
        if let IdentifierType::Undefined(r) = self {
            return write!(f, "{r}");
        } else {
            return Ok(());
        }
    }
}
    };
}

/// Unless Dynamic those are reserved words that cannot be reused otherwise.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(Serialize, Deserialize))]
pub enum IdentifierType {
    /// function declaration
    Function,
    /// _FCT_ANON_ARGS
    FCTAnonArgs,
    /// TRUE
    True,
    /// FALSE
    False,
    /// for
    For,
    /// foreach
    ForEach,
    /// if
    If,
    /// else
    Else,
    /// while
    While,
    /// repeat
    Repeat,
    /// until
    Until,
    /// local_var
    LocalVar,
    /// global_var
    GlobalVar,
    /// NULL
    Null,
    /// return
    Return,
    /// continue
    Continue,
    /// break
    Break,
    /// include
    Include,
    /// Scanning phases; can be set by category in the description block
    ACT(ACT),
    /// exit
    Exit,
    /// Undefined
    Undefined(String),
}

make_keyword_matcher! {
    function: IdentifierType::Function,
    _FCT_ANON_ARGS: IdentifierType::FCTAnonArgs,
    TRUE: IdentifierType::True,
    FALSE: IdentifierType::False,
    for: IdentifierType::For,
    foreach: IdentifierType::ForEach,
    if: IdentifierType::If,
    else: IdentifierType::Else,
    while: IdentifierType::While,
    repeat: IdentifierType::Repeat,
    until: IdentifierType::Until,
    local_var: IdentifierType::LocalVar,
    global_var: IdentifierType::GlobalVar,
    NULL: IdentifierType::Null,
    return: IdentifierType::Return,
    include: IdentifierType::Include,
    exit: IdentifierType::Exit,
    ACT_ATTACK: IdentifierType::ACT(ACT::Attack),
    ACT_DENIAL: IdentifierType::ACT(ACT::Denial),
    ACT_DESTRUCTIVE_ATTACK: IdentifierType::ACT(ACT::DestructiveAttack),
    ACT_END: IdentifierType::ACT(ACT::End),
    ACT_FLOOD: IdentifierType::ACT(ACT::Flood),
    ACT_GATHER_INFO: IdentifierType::ACT(ACT::GatherInfo),
    ACT_INIT: IdentifierType::ACT(ACT::Init),
    ACT_KILL_HOST: IdentifierType::ACT(ACT::KillHost),
    ACT_MIXED_ATTACK: IdentifierType::ACT(ACT::MixedAttack),
    ACT_SCANNER: IdentifierType::ACT(ACT::Scanner),
    ACT_SETTINGS: IdentifierType::ACT(ACT::Settings),
    continue: IdentifierType::Continue,
    break: IdentifierType::Break
}

/// Is used to identify a Token
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(Serialize, Deserialize))]
pub enum TokenKind {
    /// `(`
    LeftParen,
    /// `)`
    RightParen,
    /// `[`
    LeftBrace,
    /// `]`
    RightBrace,
    /// `{`
    LeftCurlyBracket,
    /// `}`
    RightCurlyBracket,
    /// `,`
    Comma,
    /// `.`
    Dot,
    /// `%`
    Percent,
    /// `%=`
    PercentEqual,
    /// `;`
    Semicolon,
    /// `:`
    DoublePoint,
    /// `~`
    Tilde,
    /// `^`
    Caret,
    /// `&`
    Ampersand,
    /// `&&`
    AmpersandAmpersand,
    /// `|`
    Pipe,
    /// `||`
    PipePipe,
    /// `!`
    Bang,
    /// `!=`
    BangEqual,
    /// `!~`
    BangTilde,
    /// `=`
    Equal,
    /// `==`
    EqualEqual,
    /// `=~`
    EqualTilde,
    /// `>`
    Greater,
    /// `>>`
    GreaterGreater,
    /// `>=`
    GreaterEqual,
    /// `><`
    GreaterLess,
    /// `<`
    Less,
    /// `<<`
    LessLess,
    /// `<=`
    LessEqual,
    /// `-`
    Minus,
    /// `--`
    MinusMinus,
    /// `-=`
    MinusEqual,
    /// `+`
    Plus,
    /// `+=`
    PlusEqual,
    /// `++`
    PlusPlus,
    /// `/`
    Slash,
    /// `/=`
    SlashEqual,
    /// `*`
    Star,
    /// `**`
    StarStar,
    /// `*=`
    StarEqual,
    /// `>>>`
    GreaterGreaterGreater,
    /// `>>=`
    GreaterGreaterEqual,
    /// `<<=`
    LessLessEqual,
    /// `>!<`
    GreaterBangLess,
    /// `>>>=`
    GreaterGreaterGreaterEqual,
    /// `x` is a special functionality to redo a function call n times.E.g. `send_packet( udp, pcap_active:FALSE ) x 200;`
    X,
    /// A String (")
    ///
    /// Strings can be over multiple lines and are not escapable (`a = "a\";` is valid).
    /// A string type will be cast to utf8 string.
    String(String),
    /// Data is defined Quotable (')
    ///
    /// Data can be over multiple lines and are escaped (`a = "a\";` is valid).
    /// Unlike string the data types are stored in bytes.
    Data(Vec<u8>),
    /// A Number can be either binary (0b), octal (0), base10 (1-9) or hex (0x)
    Number(i64),
    /// We currently just support 127.0.0.1 notation
    IPv4Address(String),
    /// Wrongfully identified as IpV4
    IllegalIPv4Address,
    /// An illegal Number e.g. 0b2
    IllegalNumber(NumberBase),
    /// A comment starts with # and should be ignored
    Comment,
    /// Identifier are literals that are not strings and don't start with a number
    Identifier(IdentifierType),
    /// Unclosed token. This can happen on e.g. string literals
    Unclosed(UnclosedTokenKind),
    /// Number starts with an unidentifiable base
    UnknownBase,
    /// used when the symbol is unknown
    UnknownSymbol,
}

impl Display for TokenKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenKind::LeftParen => write!(f, "("),
            TokenKind::RightParen => write!(f, ")"),
            TokenKind::LeftBrace => write!(f, "["),
            TokenKind::RightBrace => write!(f, "]"),
            TokenKind::LeftCurlyBracket => write!(f, "{{"),
            TokenKind::RightCurlyBracket => write!(f, "}}"),
            TokenKind::Comma => write!(f, ","),
            TokenKind::Dot => write!(f, "."),
            TokenKind::Percent => write!(f, "%"),
            TokenKind::PercentEqual => write!(f, "%="),
            TokenKind::Semicolon => write!(f, ";"),
            TokenKind::DoublePoint => write!(f, ":"),
            TokenKind::Tilde => write!(f, "~"),
            TokenKind::Caret => write!(f, "^"),
            TokenKind::Ampersand => write!(f, "&"),
            TokenKind::AmpersandAmpersand => write!(f, "&&"),
            TokenKind::Pipe => write!(f, "|"),
            TokenKind::PipePipe => write!(f, "||"),
            TokenKind::Bang => write!(f, "!"),
            TokenKind::BangEqual => write!(f, "!="),
            TokenKind::BangTilde => write!(f, "!~"),
            TokenKind::Equal => write!(f, "="),
            TokenKind::EqualEqual => write!(f, "=="),
            TokenKind::EqualTilde => write!(f, "=~"),
            TokenKind::Greater => write!(f, ">"),
            TokenKind::GreaterGreater => write!(f, ">>"),
            TokenKind::GreaterEqual => write!(f, ">="),
            TokenKind::GreaterLess => write!(f, "><"),
            TokenKind::Less => write!(f, "<"),
            TokenKind::LessLess => write!(f, "<<"),
            TokenKind::LessEqual => write!(f, "<="),
            TokenKind::Minus => write!(f, "-"),
            TokenKind::MinusMinus => write!(f, "--"),
            TokenKind::MinusEqual => write!(f, "-="),
            TokenKind::Plus => write!(f, "+"),
            TokenKind::PlusEqual => write!(f, "+="),
            TokenKind::PlusPlus => write!(f, "++"),
            TokenKind::Slash => write!(f, "/"),
            TokenKind::SlashEqual => write!(f, "/="),
            TokenKind::Star => write!(f, "*"),
            TokenKind::StarStar => write!(f, "**"),
            TokenKind::StarEqual => write!(f, "*="),
            TokenKind::GreaterGreaterGreater => write!(f, ">>>"),
            TokenKind::GreaterGreaterEqual => write!(f, ">>="),
            TokenKind::LessLessEqual => write!(f, "<<="),
            TokenKind::GreaterBangLess => write!(f, ">!<"),
            TokenKind::GreaterGreaterGreaterEqual => write!(f, ">>>="),
            TokenKind::X => write!(f, "X"),
            TokenKind::String(x) => write!(f, "\"{x}\""),
            TokenKind::Number(x) => write!(f, "{x}"),
            TokenKind::IPv4Address(x) => write!(f, "{x}"),
            TokenKind::IllegalIPv4Address => write!(f, "IllegalIPv4Address"),
            TokenKind::IllegalNumber(_) => write!(f, "IllegalNumber"),
            TokenKind::Comment => write!(f, "Comment"),
            TokenKind::Identifier(x) => write!(f, "{}", x),
            TokenKind::Unclosed(x) => write!(f, "Unclosed{x:?}"),
            TokenKind::UnknownBase => write!(f, "UnknownBase"),
            TokenKind::UnknownSymbol => write!(f, "UnknownSymbol"),
            TokenKind::Data(x) => write!(f, "{x:?}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Contains the TokenType as well as the position.
#[cfg_attr(test, derive(Serialize, Deserialize))]
pub struct Token {
    /// The kind of a token
    pub kind: TokenKind,
    /// The line and the column of the start of the token
    pub line_column: (usize, usize),
    /// Byte position
    pub position: (usize, usize),
}

impl Default for Token {
    fn default() -> Self {
        Token {
            kind: TokenKind::UnknownSymbol,
            line_column: (0, 0),
            position: (0, 0),
        }
    }
}

impl Token {
    /// Returns UnknownSymbol without line column or position
    pub fn unexpected_none() -> Self {
        Self {
            kind: TokenKind::UnknownSymbol,
            line_column: (0, 0),
            position: (0, 0),
        }
    }

    pub fn identifier(&self) -> Result<String, InterpretError> {
        match self.kind() {
            TokenKind::Identifier(IdentifierType::Undefined(x)) => Ok(x.to_owned()),
            cat => Err(InterpretError::wrong_kind(cat)),
        }
    }
}

impl Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "'{}'", self.kind,)
    }
}

impl Token {
    pub fn kind(&self) -> &TokenKind {
        &self.kind
    }

    /// Returns the line number of the token
    pub fn line(&self) -> usize {
        self.line_column.0
    }

    /// Returns the column number of the token
    pub fn column(&self) -> usize {
        self.line_column.1
    }

    /// Returns true when a Token is faulty
    ///
    /// A Token is faulty when it is a syntactical error like
    /// - [TokenKind::IllegalIPv4Address]
    /// - [TokenKind::Unclosed]
    /// - [TokenKind::UnknownBase]
    /// - [TokenKind::UnknownSymbol]
    /// - [TokenKind::IllegalNumber]
    pub fn is_faulty(&self) -> bool {
        matches!(
            self.kind(),
            TokenKind::IllegalIPv4Address
                | TokenKind::IllegalNumber(_)
                | TokenKind::Unclosed(_)
                | TokenKind::UnknownBase
                | TokenKind::UnknownSymbol
        )
    }
}
