// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::{
    error::SyntaxError,
    lexer::{End, Lexer},
    token::{Category, Token},
    unclosed_token, unexpected_token, Statement,
};

pub(crate) trait Variables {
    /// Parses variables, function calls.
    fn parse_variable(&mut self, token: Token) -> Result<(End, Statement), SyntaxError>;
}

pub(crate) trait CommaGroup {
    fn parse_comma_group(
        &mut self,
        category: Category,
    ) -> Result<(End, Vec<Statement>), SyntaxError>;
}

impl<'a> CommaGroup for Lexer<'a> {
    fn parse_comma_group(
        &mut self,
        category: Category,
    ) -> Result<(End, Vec<Statement>), SyntaxError> {
        let mut params = vec![];
        let mut end = End::Continue;
        while let Some(token) = self.peek() {
            if *token.category() == category {
                self.token();
                end = End::Done(token);
                break;
            }
            let (stmtend, param) =
                self.statement(0, &|c| c == &category || c == &Category::Comma)?;
            match param {
                Statement::Parameter(nparams) => params.extend_from_slice(&nparams),
                param => params.push(param),
            }
            match stmtend {
                End::Done(endcat) => {
                    if endcat.category() == &category {
                        end = End::Done(endcat);
                        break;
                    }
                }
                End::Continue => {}
            };
        }
        Ok((end, params))
    }
}

impl<'a> Variables for Lexer<'a> {
    fn parse_variable(&mut self, token: Token) -> Result<(End, Statement), SyntaxError> {
        if !matches!(
            token.category(),
            Category::Identifier(crate::IdentifierType::Undefined(_))
        ) {
            return Err(unexpected_token!(token));
        }
        use End::*;

        if let Some(nt) = self.peek() {
            match nt.category() {
                Category::LeftParen => {
                    self.token();
                    let (end, params) = self.parse_comma_group(Category::RightParen)?;
                    return match end {
                        Done(end) => Ok((Continue, Statement::Call(token, params, end))),
                        Continue => Err(unclosed_token!(nt)),
                    };
                }
                Category::LeftBrace => {
                    self.token();
                    let (end, lookup) = self.statement(0, &|c| c == &Category::RightBrace)?;
                    let lookup = lookup.as_returnable_or_err()?;
                    return match end {
                        Done(end) => Ok((
                            Continue,
                            Statement::Array(token, Some(Box::new(lookup)), Some(end)),
                        )),
                        Continue => Err(unclosed_token!(token)),
                    };
                }
                _ => {}
            }
        }
        Ok((Continue, Statement::Variable(token)))
    }
}

#[cfg(test)]
mod test {
    use crate::{
        parse, {AssignOrder, Statement},
    };

    use Statement::*;

    fn result(code: &str) -> Statement {
        parse(code).next().unwrap().unwrap()
    }

    #[test]
    fn variables() {
        assert!(matches!(result("a;"), Variable(_)));
    }

    #[test]
    fn arrays() {
        assert!(matches!(result("a[0];"), Array(..)));
        match result("a = [1, 2, 3];") {
            Assign(super::Category::Equal, AssignOrder::AssignReturn, arr, _) => {
                assert!(matches!(*arr, Array(..)))
            }
            actual => unreachable!("{actual} must be an assign statement"),
        }

        match result("a[0] = [1, 2, 4];") {
            Assign(super::Category::Equal, AssignOrder::AssignReturn, arr, _) => {
                assert!(matches!(*arr, Array(..)))
            }
            actual => unreachable!("{actual} must be an assign statement"),
        }
    }

    #[test]
    fn anon_function_call() {
        assert!(matches!(result("a(1, 2, 3);"), Call(..)))
    }

    #[test]
    fn named_function_call() {
        assert!(matches!(
            result("script_tag(name:\"cvss_base\", value:1 + 1 % 2);"),
            Call(..)
        ));
    }
}
