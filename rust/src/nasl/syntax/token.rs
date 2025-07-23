// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! This module defines the TokenTypes as well as Token and extends Cursor with advance_token
use std::{fmt::Display, net::Ipv4Addr};

use crate::{
    nasl::{error::Span, utils::function::bytes_to_str},
    storage::items::nvt::ACT,
};

use crate::nasl::error::Spanned;

/// A reserved NASL keyword.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Keyword {
    /// function declaration
    Function,
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
    continue, Keyword::Continue,
    break, Keyword::Break
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ident {
    ident: String,
    span: Span,
}

impl Ident {
    pub(crate) fn to_str(&self) -> &str {
        &self.ident
    }

    pub(crate) fn new(ident: String, span: Span) -> Self {
        Self { ident, span }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LiteralKind {
    /// A String (enclosed in ")
    ///
    /// Strings can be over multiple lines and are not escapable (`a = "a\";` is valid).
    /// Strings have to be valid UTF8.
    String(String),
    /// A raw byte string (enclosed in ')
    ///
    /// Data can be over multiple lines and are escaped (`a = "a\";` is valid).
    /// Unlike string, the data types are stored in bytes.
    Data(Vec<u8>),
    /// A Number can be either binary (0b), octal (0), base10 (1-9) or hex (0x)
    Number(i64),
    /// An IP V4 address. We currently just support 127.0.0.1 notation
    IPv4Address(Ipv4Addr),
    /// A boolean.
    Boolean(bool),
    /// Attack category
    AttackCategory(ACT),
    /// Null
    Null,
    /// Anonymous function args
    FCTAnonArgs,
}

impl LiteralKind {
    pub fn from_keyword(lookup: &str) -> Option<Self> {
        match lookup {
            "NULL" => Some(Self::Null),
            "Null" => Some(Self::Null),
            "FALSE" => Some(Self::Boolean(false)),
            "TRUE" => Some(Self::Boolean(true)),
            "ACT_ATTACK" => Some(Self::AttackCategory(ACT::Attack)),
            "ACT_DENIAL" => Some(Self::AttackCategory(ACT::Denial)),
            "ACT_DESTRUCTIVE_ATTACK" => Some(Self::AttackCategory(ACT::DestructiveAttack)),
            "ACT_END" => Some(Self::AttackCategory(ACT::End)),
            "ACT_FLOOD" => Some(Self::AttackCategory(ACT::Flood)),
            "ACT_GATHER_INFO" => Some(Self::AttackCategory(ACT::GatherInfo)),
            "ACT_INIT" => Some(Self::AttackCategory(ACT::Init)),
            "ACT_KILL_HOST" => Some(Self::AttackCategory(ACT::KillHost)),
            "ACT_MIXED_ATTACK" => Some(Self::AttackCategory(ACT::MixedAttack)),
            "ACT_SCANNER" => Some(Self::AttackCategory(ACT::Scanner)),
            "ACT_SETTINGS" => Some(Self::AttackCategory(ACT::Settings)),
            "_FCT_ANON_ARGS" => Some(Self::FCTAnonArgs),
            _ => None,
        }
    }
}

impl Literal {
    pub(crate) fn into_string(self) -> Option<String> {
        match self.kind {
            LiteralKind::String(s) => Some(s),
            LiteralKind::Data(bytes) => Some(bytes_to_str(&bytes)),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Literal {
    pub kind: LiteralKind,
    span: Span,
}

impl Literal {
    pub(crate) fn new(kind: LiteralKind, span: Span) -> Self {
        Self { kind, span }
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
    Colon,
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
            TokenKind::Colon => write!(f, ":"),
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
            TokenKind::Keyword(kw) => write!(f, "{kw}"),
            TokenKind::Ident(ident) => write!(f, "{ident}"),
            TokenKind::Literal(literal) => match &literal.kind {
                LiteralKind::Number(num) => write!(f, "{num}"),
                LiteralKind::String(s) => write!(f, "\"{s}\""),
                LiteralKind::Data(data) => write!(f, "{data:?}"),
                LiteralKind::IPv4Address(ip) => write!(f, "{ip}"),
                LiteralKind::Boolean(b) => write!(f, "{b}"),
                LiteralKind::Null => write!(f, "Null"),
                LiteralKind::AttackCategory(c) => write!(f, "{c}"),
                LiteralKind::FCTAnonArgs => write!(f, "_FCT_ANON_ARGS"),
            },
            TokenKind::Eof => write!(f, ""),
        }
    }
}

/// Contains the TokenType as well as the position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    /// The kind of a token
    pub kind: TokenKind,
    span: Span,
}

impl Token {
    pub fn new(kind: TokenKind, span: Span) -> Self {
        Self { kind, span }
    }

    pub(crate) fn span(&self) -> Span {
        // TODO remove this and make span the stored type
        self.span
    }
}

impl Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "'{}'", self.kind,)
    }
}

impl Spanned for Ident {
    fn span(&self) -> Span {
        self.span
    }
}

impl Spanned for &Ident {
    fn span(&self) -> Span {
        self.span
    }
}

impl Spanned for Literal {
    fn span(&self) -> Span {
        self.span
    }
}

impl Spanned for &Literal {
    fn span(&self) -> Span {
        self.span
    }
}
