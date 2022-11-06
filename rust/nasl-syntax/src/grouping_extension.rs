use crate::{
    parser::{AssignCategory, Statement, TokenError},
    token::{Category, Token}, lexer::Lexer,
};

pub(crate) trait Grouping {
    fn parse_paren(&mut self, token: Token) -> Result<Statement, TokenError>;
}

impl<'a> Grouping for Lexer<'a> {

    fn parse_paren(&mut self, token: Token) -> Result<Statement, TokenError> {
        let lhs = self.expression_bp(0, Category::RightParen)?;
        let actual = self
            .previous_token
            .map_or(Category::Equal, |t| t.category());
        if actual != Category::RightParen {
            Err(TokenError::unclosed(token))
        } else {
            self.previous_token = None;
            match lhs {
                Statement::Assign(_, token, stmt) => {
                    Ok(Statement::Assign(AssignCategory::AssignReturn, token, stmt))
                }
                _ => Ok(lhs),
            }
        }
    }
}

