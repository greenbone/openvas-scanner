// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]
mod error;
mod grammar;
mod grouping_extension;
mod keyword_extension;
mod lexer;
mod loader;
mod naslvalue;
mod operation;
pub mod parser;
mod prefix_extension;
mod token;
mod tokenizer;

pub use crate::storage::item::ACT;
pub use error::{ErrorKind, SyntaxError};
pub use grammar::Ast;
pub use grammar::{AssignOrder, Declaration, Statement, StatementKind};
pub(super) use lexer::Lexer;
pub use loader::*;
pub use naslvalue::*;
pub use token::Ident;
pub use token::Keyword;
pub use token::Token;
pub use token::TokenKind;
pub use tokenizer::Tokenizer;
pub use tokenizer::TokenizerError;
