// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! This module defines the TokenTypes as well as Token and extends Cursor with advance_token
use std::{fmt::Display, net::Ipv4Addr};

use crate::{
    nasl::{error::Span, interpreter::InterpretError},
    storage::items::nvt::ACT,
};

use super::CharIndex;

/// A reserved NASL keyword.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Keyword {
    /// function declaration
    Function,
    /// _FCT_ANON_ARGS
    FCTAnonArgs,
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
}

macro_rules! make_keyword_matcher {
    ($($matcher:ident, $define:expr),+) => {
        impl Keyword {
            /// Creates a new keyword based on a string identifier
            pub fn new(keyword: &str) -> Option<Self> {
                match keyword {
                    $(
                    stringify!($matcher) => Some($define),
                    )*
                    _ => None,
                }
            }
        }

        impl std::fmt::Display for Keyword {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                // $define is not a pattern but expr, so in the
                // name of simplicity we use a chained if here
                $(
                    if *self == $define {
                        return write!(f, stringify!($matcher));
                    }
                )*
                unreachable!()
            }
        }
    }
}

make_keyword_matcher! {
    function, Keyword::Function,
    _FCT_ANON_ARGS, Keyword::FCTAnonArgs,
    for, Keyword::For,
    foreach, Keyword::ForEach,
    if, Keyword::If,
    else, Keyword::Else,
    while, Keyword::While,
    repeat, Keyword::Repeat,
    until, Keyword::Until,
    local_var, Keyword::LocalVar,
    global_var, Keyword::GlobalVar,
    return, Keyword::Return,
    include, Keyword::Include,
    exit, Keyword::Exit,
    ACT_ATTACK, Keyword::ACT(ACT::Attack),
    ACT_DENIAL, Keyword::ACT(ACT::Denial),
    ACT_DESTRUCTIVE_ATTACK, Keyword::ACT(ACT::DestructiveAttack),
    ACT_END, Keyword::ACT(ACT::End),
    ACT_FLOOD, Keyword::ACT(ACT::Flood),
    ACT_GATHER_INFO, Keyword::ACT(ACT::GatherInfo),
    ACT_INIT, Keyword::ACT(ACT::Init),
    ACT_KILL_HOST, Keyword::ACT(ACT::KillHost),
    ACT_MIXED_ATTACK, Keyword::ACT(ACT::MixedAttack),
    ACT_SCANNER, Keyword::ACT(ACT::Scanner),
    ACT_SETTINGS, Keyword::ACT(ACT::Settings),
    continue, Keyword::Continue,
    break, Keyword::Break
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ident(pub String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Literal {
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
    /// An IP address. We currently just support 127.0.0.1 notation
    IPv4Address(Ipv4Addr),
    /// A boolean.
    Boolean(bool),
    /// Null
    Null,
}

impl Literal {
    pub fn from_keyword(lookup: &str) -> Option<Self> {
        match lookup {
            "NULL" => Some(Self::Null),
            "FALSE" => Some(Self::Boolean(false)),
            "TRUE" => Some(Self::Boolean(true)),
            _ => None,
        }
    }
}

/// Is used to identify a Token
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenKind {
    /// `(`
    LeftParen,
    /// `)`
    RightParen,
    /// `[`
    LeftBracket,
    /// `]`
    RightBracket,
    /// `{`
    LeftBrace,
    /// `}`
    RightBrace,
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
    /// A literal, such as a number, string, data or IP address
    Literal(Literal),
    /// Special keywords reserved within NASL.
    Keyword(Keyword),
    /// An identifier for a variable or function.
    Ident(Ident),
    /// End of file
    Eof,
}

impl Display for TokenKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenKind::LeftParen => write!(f, "("),
            TokenKind::RightParen => write!(f, ")"),
            TokenKind::LeftBracket => write!(f, "["),
            TokenKind::RightBracket => write!(f, "]"),
            TokenKind::LeftBrace => write!(f, "{{"),
            TokenKind::RightBrace => write!(f, "}}"),
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
            TokenKind::Keyword(kw) => write!(f, "{}", kw),
            TokenKind::Ident(ident) => write!(f, "{}", ident.0),
            TokenKind::Literal(Literal::Number(num)) => write!(f, "{num}"),
            TokenKind::Literal(Literal::String(s)) => write!(f, "\"{s}\""),
            TokenKind::Literal(Literal::Data(data)) => write!(f, "{data:?}"),
            TokenKind::Literal(Literal::IPv4Address(ip)) => write!(f, "{ip}"),
            TokenKind::Literal(Literal::Boolean(b)) => write!(f, "{}", b),
            TokenKind::Literal(Literal::Null) => write!(f, "Null"),
            TokenKind::Eof => write!(f, ""),
        }
    }
}

/// Contains the TokenType as well as the position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    /// The kind of a token
    pub kind: TokenKind,
    /// Byte position
    pub position: (usize, usize),
}

impl Token {
    // TODO get rid of this
    pub fn identifier(&self) -> Result<String, InterpretError> {
        match self.kind() {
            TokenKind::Ident(ident) => Ok(ident.0.clone()),
            kind => Err(InterpretError::wrong_kind(kind)),
        }
    }

    // TODO get rid of this
    pub fn literal(&self) -> Result<&Literal, InterpretError> {
        match self.kind() {
            TokenKind::Literal(lit) => Ok(lit),
            kind => Err(InterpretError::wrong_kind(kind)),
        }
    }

    // TODO get rid of this
    pub fn sentinel() -> Token {
        Self {
            kind: TokenKind::X,
            position: (0, 0),
        }
    }

    pub fn start(&self) -> usize {
        self.position.0
    }

    pub fn end(&self) -> usize {
        self.position.1
    }

    pub(crate) fn span(&self) -> Span {
        // TODO remove this and make span the stored type
        Span::new(CharIndex(self.start()), CharIndex(self.end()))
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
}
