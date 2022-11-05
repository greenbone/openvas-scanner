
use crate::{
    operator_precedence_parser::{Lexer, Operator},
    parser::{AssignCategory, Statement, TokenError},
    token::{Category, Token}, assign_operator_extension::AssignOperator, keyword_extension::Keywords, variable_extension::Variables,
};
pub(crate) trait Prefix {
    fn prefix_statement(&mut self, token: Token, abort: Category) -> Result<Statement, TokenError>;
}

fn prefix_binding_power(token: Token) -> Result<u8, TokenError> {
    match token.category() {
        Category::Plus | Category::Minus => Ok(9),
        _ => Err(TokenError::unexpected_token(token)),
    }
}

impl<'a> Prefix for Lexer<'a> {
    /// Handles statements before operation statements get handled.
    /// This is mostly done to detect statements that should not be weighted and executed before hand
    fn prefix_statement(&mut self, token: Token, abort: Category) -> Result<Statement, TokenError> {
        let op = Operator::from(token);
        match op {
            Operator::Operator(kind) => {
                let bp = prefix_binding_power(token)?;
                let rhs = self.expression_bp(bp, abort)?;
                Ok(Statement::Operator(kind, vec![rhs]))
            }
            Operator::Assign(_) => Err(TokenError::unexpected_token(token)),
            Operator::Primitive(token) => Ok(Statement::Primitive(token)),
            Operator::Variable(token) => self.parse_variable(token),
            Operator::Grouping(category) => {
                if category == Category::LeftParen {
                    self.parse_paren(token)
                } else {
                    Err(TokenError::unexpected_token(token))
                }
            }
            Operator::AssignOperator(_, operation, amount) => {
                self.parse_prefix_assign_operator(token, operation, amount)
            }
            Operator::Keyword(keyword) => self.parse_keyword(keyword, token),
        }
    }

}


