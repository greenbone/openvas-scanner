// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Defines Operations used in Lexer to be transformed to Statements.
use crate::token::{Category, IdentifierType, Token};

/// Is defining different OPerations to control the infix, postfix or infix handling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Operation {
    /// Operator are mostly used in infix.
    ///
    /// To add a new Operator it must most likely define a binding power in infix_extension.
    Operator(Category),
    /// Although Assign is actually a Operator it is defined extra to make postfix handling easier.
    ///
    /// For a new Assign operation you most most likely define it in prefix binding power like an Operator.
    Assign(Category),
    /// Groupings are handled mostly in prefix and maybe postfix.
    Grouping(Category),
    /// Is handled in prefix.
    Variable,
    /// Is handled in prefix.
    Primitive,
    /// Is handled in prefix.
    Keyword(IdentifierType),
    /// Empty statement
    NoOp,
}

impl Operation {
    /// May create a new Operation based on given token. It returns None when the token.category is unknown.
    pub(crate) fn new(token: &Token) -> Option<Operation> {
        match token.category() {
            Category::Plus
            | Category::Star
            | Category::Slash
            | Category::Minus
            | Category::Percent
            | Category::LessLess
            | Category::GreaterGreater
            | Category::GreaterGreaterGreater
            | Category::Tilde
            | Category::Ampersand
            | Category::Pipe
            | Category::Caret
            | Category::Bang
            | Category::EqualTilde
            | Category::BangTilde
            | Category::GreaterLess
            | Category::GreaterBangLess
            | Category::AmpersandAmpersand
            | Category::PipePipe
            | Category::EqualEqual
            | Category::BangEqual
            | Category::Greater
            | Category::Less
            | Category::GreaterEqual
            | Category::LessEqual
            | Category::X
            | Category::StarStar => Some(Operation::Operator(token.category().clone())),
            Category::Equal
            | Category::MinusEqual
            | Category::PlusEqual
            | Category::SlashEqual
            | Category::StarEqual
            | Category::GreaterGreaterEqual
            | Category::LessLessEqual
            | Category::GreaterGreaterGreaterEqual
            | Category::PlusPlus
            | Category::Semicolon
            | Category::DoublePoint
            | Category::PercentEqual
            | Category::MinusMinus => Some(Operation::Assign(token.category().clone())),
            Category::String(_)
            | Category::Data(_)
            | Category::Number(_)
            | Category::IPv4Address(_) => Some(Operation::Primitive),
            Category::LeftParen
            | Category::LeftBrace
            | Category::LeftCurlyBracket
            | Category::Comma => Some(Operation::Grouping(token.category().clone())),
            Category::Identifier(IdentifierType::Undefined(_)) => Some(Operation::Variable),
            Category::Identifier(keyword) => Some(Operation::Keyword(keyword.clone())),
            Category::Comment => Some(Operation::NoOp),
            _ => None,
        }
    }
}
