use crate::{
    assign_operator_extension::AssignOperator,
    error::TokenError,
    grouping_extension::Grouping,
    keyword_extension::Keywords,
    lexer::Lexer,
    lexer::Statement,
    operation::Operation,
    token::{Category, Token},
    unexpected_token,
    variable_extension::Variables,
};
pub(crate) trait Prefix {
    fn prefix_statement(
        &mut self,
        token: Token,
        abort: Category,
    ) -> Result<(PrefixState, Statement), TokenError>;
}

fn prefix_binding_power(token: Token) -> Result<u8, TokenError> {
    match token.category() {
        Category::Plus | Category::Minus => Ok(9),
        _ => Err(unexpected_token!(token)),
    }
}

/// Is used by prefix_statement to dertermine if the expression loop should continue or break
/// This is needed when the complete statement parsing is done for e.g. if or block statements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PrefixState {
    Continue,
    Break,
}

impl<'a> Prefix for Lexer<'a> {
    /// Handles statements before operation statements get handled.
    /// This is mostly done to detect statements that should not be weighted and executed before hand
    fn prefix_statement(
        &mut self,
        token: Token,
        abort: Category,
    ) -> Result<(PrefixState, Statement), TokenError> {
        use PrefixState::*;
        let op = Operation::new(token).ok_or_else(|| unexpected_token!(token))?;
        match op {
            Operation::Operator(kind) => {
                let bp = prefix_binding_power(token)?;
                let rhs = self.expression_bp(bp, abort)?;
                Ok((Continue, Statement::Operator(kind, vec![rhs])))
            }
            Operation::Assign(_) => Err(unexpected_token!(token)),
            Operation::Primitive(token) => Ok((Continue, Statement::Primitive(token))),
            Operation::Variable(token) => self.parse_variable(token).map(|stmt| (Continue, stmt)),
            Operation::Grouping(_) => self.parse_grouping(token),
            Operation::AssignOperator(_, operation, amount) => self
                .parse_prefix_assign_operator(token, operation, amount)
                .map(|stmt| (Continue, stmt)),
            Operation::Keyword(keyword) => self.parse_keyword(keyword, token),
            Operation::NoOp(_) => Ok((Break, Statement::NoOp(Some(token)))),
        }
    }
}

#[cfg(test)]
mod test {

    use crate::{
        lexer::expression,
        lexer::Statement,
        token::{Base, Category, StringCategory, Token, Tokenizer},
    };

    use Base::*;
    use Category::*;
    use Statement::*;

    fn result(code: &str) -> Statement {
        let tokenizer = Tokenizer::new(code);
        expression(tokenizer).unwrap()
    }
    fn token(category: Category, start: usize, end: usize) -> Token {
        Token {
            category,
            position: (start, end),
        }
    }

    #[test]
    fn single_statement() {
        assert_eq!(result("1"), Primitive(token(Number(Base10), 0, 1)));
        assert_eq!(
            result("'a'"),
            Primitive(token(String(StringCategory::Quoteable), 1, 2))
        );
    }

    #[test]
    fn comments_are_noop() {
        assert_eq!(result("# Comment"), NoOp(Some(token(Comment, 0, 9))));
    }
}
