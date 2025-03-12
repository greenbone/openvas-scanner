// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines Operations used in Lexer to be transformed to Statements.
use super::token::{Keyword, Token, TokenKind};

/// Is defining different OPerations to control the infix, postfix or infix handling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Operation {
    /// Operator are mostly used in infix.
    ///
    /// To add a new Operator it must most likely define a binding power in infix_extension.
    Operator(TokenKind),
    /// Although Assign is actually a Operator it is defined extra to make postfix handling easier.
    ///
    /// For a new Assign operation you most most likely define it in prefix binding power like an Operator.
    Assign(TokenKind),
    /// Groupings are handled mostly in prefix and maybe postfix.
    Grouping(TokenKind),
    /// Is handled in prefix.
    Variable,
    /// Is handled in prefix.
    Primitive,
    /// Is handled in prefix.
    Keyword(Keyword),
}

impl Operation {
    /// May create a new Operation based on given token. It returns None when the token.kind is unknown.
    pub(crate) fn new(token: &Token) -> Option<Operation> {
        match token.kind() {
            TokenKind::Plus
            | TokenKind::Star
            | TokenKind::Slash
            | TokenKind::Minus
            | TokenKind::Percent
            | TokenKind::LessLess
            | TokenKind::GreaterGreater
            | TokenKind::GreaterGreaterGreater
            | TokenKind::Tilde
            | TokenKind::Ampersand
            | TokenKind::Pipe
            | TokenKind::Caret
            | TokenKind::Bang
            | TokenKind::EqualTilde
            | TokenKind::BangTilde
            | TokenKind::GreaterLess
            | TokenKind::GreaterBangLess
            | TokenKind::AmpersandAmpersand
            | TokenKind::PipePipe
            | TokenKind::EqualEqual
            | TokenKind::BangEqual
            | TokenKind::Greater
            | TokenKind::Less
            | TokenKind::GreaterEqual
            | TokenKind::LessEqual
            | TokenKind::X
            | TokenKind::StarStar => Some(Operation::Operator(token.kind().clone())),
            TokenKind::Equal
            | TokenKind::MinusEqual
            | TokenKind::PlusEqual
            | TokenKind::SlashEqual
            | TokenKind::StarEqual
            | TokenKind::GreaterGreaterEqual
            | TokenKind::LessLessEqual
            | TokenKind::GreaterGreaterGreaterEqual
            | TokenKind::PlusPlus
            | TokenKind::Semicolon
            | TokenKind::DoublePoint
            | TokenKind::PercentEqual
            | TokenKind::MinusMinus => Some(Operation::Assign(token.kind().clone())),
            TokenKind::String(_)
            | TokenKind::Data(_)
            | TokenKind::Number(_)
            | TokenKind::IPv4Address(_) => Some(Operation::Primitive),
            TokenKind::LeftParen
            | TokenKind::LeftBrace
            | TokenKind::LeftCurlyBracket
            | TokenKind::Comma => Some(Operation::Grouping(token.kind().clone())),
            TokenKind::Keyword(Keyword::Undefined(_)) => Some(Operation::Variable),
            TokenKind::Keyword(keyword) => Some(Operation::Keyword(keyword.clone())),
            _ => None,
        }
    }
}
