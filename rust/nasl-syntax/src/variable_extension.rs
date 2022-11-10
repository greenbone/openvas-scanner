use crate::{
    error::SyntaxError,
    grouping_extension::Grouping,
    lexer::Lexer,
    lexer::Statement,
    token::{Category, Token},
    unexpected_token,
};

pub(crate) trait Variables {
    /// Parses variables, function calls.
    fn parse_variable(&mut self, token: Token) -> Result<Statement, SyntaxError>;
}

impl<'a> Variables for Lexer<'a> {
    fn parse_variable(&mut self, token: Token) -> Result<Statement, SyntaxError> {
        if token.category() != Category::Identifier(None) {
            return Err(unexpected_token!(token));
        }

        if let Some(nt) = self.token() {
            self.unhandled_token = Some(nt);
            if nt.category() == Category::LeftParen {
                self.unhandled_token = None;
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
        lexer::Statement,
        parse,
        token::{Base, Category, Token},
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
        parse(code).next().unwrap().unwrap()
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
