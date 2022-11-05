use crate::{
    operator_precedence_parser::Lexer,
    parser::{Statement, TokenError},
    token::{Category, Token},
};

pub(crate) trait Variables {
    fn parse_variable(&mut self, token: Token) -> Result<Statement, TokenError>;
    fn flatten_parameter(
        &mut self,
        lhs: Statement,
        abort: Category,
    ) -> Result<Statement, TokenError>;
}

impl<'a> Variables for Lexer<'a> {
    fn parse_variable(&mut self, token: Token) -> Result<Statement, TokenError> {
        if token.category() != Category::Identifier(None) {
            return Err(TokenError::unexpected_token(token));
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

    fn flatten_parameter(
        &mut self,
        lhs: Statement,
        abort: Category,
    ) -> Result<Statement, TokenError> {
        let mut lhs = match lhs {
            Statement::Parameter(x) => x,
            x => vec![x],
        };
        match self.expression_bp(0, abort)? {
            Statement::Parameter(mut x) => lhs.append(&mut x),
            x => lhs.push(x),
        };
        Ok(Statement::Parameter(lhs))
    }
}

#[cfg(test)]
mod test {
    use crate::{
        operator_precedence_parser::expression,
        parser::Statement,
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
