use crate::{
    lexer::Statement,
    error::TokenError,
    token::{Category, Token}, grouping_extension::Grouping, lexer::Lexer, unexpected_token,
};

pub(crate) trait Variables {
    fn parse_variable(&mut self, token: Token) -> Result<Statement, TokenError>;
}

impl<'a> Variables for Lexer<'a> {
    fn parse_variable(&mut self, token: Token) -> Result<Statement, TokenError> {
        if token.category() != Category::Identifier(None) {
            return Err(unexpected_token!(token));
        }

        if let Some(nt) = self.next() {
            self.previous_token = Some(nt);
            if nt.category() == Category::LeftParen {
                self.previous_token = None;
                let parameter = self.parse_paren(nt)?;
                return Ok(Statement::Call(token, Box::new(parameter)));
            }
        }
        Ok(Statement::Variable(token))
    }

}

#[cfg(test)]
mod test {
    use crate::{
        lexer::expression,
        lexer::Statement,
        token::{Base, Category, Token, Tokenizer},
    };

    use Base::*;
    use Category::*;
    use Statement::*;

    fn token(category: Category, start: usize, end: usize) -> Token {
        Token {
            category,
            position: (start, end),
        }
    }

    fn result(code: &str) -> Statement {
        let tokenizer = Tokenizer::new(code);
        expression(tokenizer).unwrap()
    }

    #[test]
    fn variables() {
        assert_eq!(result("a"), Variable(token(Identifier(None), 0, 1)));
        let fn_name = token(Identifier(None), 0, 1);
        let args = Box::new(Parameter(vec![
            Primitive(token(Number(Base10), 2, 3)),
            Primitive(token(Number(Base10), 5, 6)),
            Primitive(token(Number(Base10), 8, 9)),
        ]));

        assert_eq!(result("a(1, 2, 3)"), Call(fn_name, args));
    }
}
