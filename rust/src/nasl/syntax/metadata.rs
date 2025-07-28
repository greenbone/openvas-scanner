use crate::nasl::syntax::parser::ErrorKind;
use crate::nasl::syntax::parser::Result;

use super::Keyword;
use super::TokenKind;
use super::grammar::Ast;
use super::grammar::Atom;
use super::grammar::Expr;
use super::grammar::Statement;
use super::parser::Error;
use super::parser::cursor::Peek;
use super::{grammar::If, parser::Parse};

pub struct DescriptionBlock {
    stmts: Vec<Statement>,
}

impl DescriptionBlock {
    pub(crate) fn into_ast(self) -> Ast {
        Ast::new(self.stmts)
    }
}

impl Parse for DescriptionBlock {
    fn parse(parser: &mut super::Parser) -> Result<Self> {
        while !parser.token_matches(TokenKind::Keyword(Keyword::If)) {
            parser.advance();
        }
        let mut if_: If = parser.parse()?;
        let (condition, block) = if_.if_branches.remove(0);
        check_condition(condition)?;
        Ok(Self { stmts: block.items })
    }
}

fn check_condition(condition: Expr) -> Result<()> {
    if let Expr::Atom(Atom::Ident(ref ident)) = condition {
        if ident.to_string() == "description" {
            return Ok(());
        }
    }
    let err: Error = ErrorKind::InvalidDescriptionBlock(
        "Invalid condition. Expected if (description) { ... }.".to_string(),
    )
    .into();
    Err(err.with_span(&condition))
}
