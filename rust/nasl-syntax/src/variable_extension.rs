// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::{
    error::SyntaxError,
    lexer::{End, Lexer},
    token::Category,
    Statement, StatementKind,
};

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
            match param.kind() {
                StatementKind::Parameter(nparams) => params.extend_from_slice(nparams),
                _ => params.push(param),
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

        self.depth = 0;
        Ok((end, params))
    }
}

#[cfg(test)]
mod test {
    use crate::{
        parse, Statement, {AssignOrder, StatementKind},
    };

    use StatementKind::*;

    fn result(code: &str) -> Statement {
        parse(code).next().unwrap().unwrap()
    }

    #[test]
    fn variables() {
        assert_eq!(result("a;").kind(), &StatementKind::Variable)
    }

    #[test]
    fn arrays() {
        assert!(matches!(result("a[0];").kind(), Array(Some(_))));
        let re = result("a = [1, 2, 3];");
        match re.kind() {
            Assign(super::Category::Equal, AssignOrder::AssignReturn, arr, _) => {
                assert!(matches!(arr.kind(), Array(None)))
            }
            _ => panic!("{re} must be an assign statement"),
        }

        let re = result("a[0] = [1, 2, 4];");
        match re.kind() {
            Assign(super::Category::Equal, AssignOrder::AssignReturn, arr, _) => {
                assert!(matches!(arr.kind(), &Array(Some(_))))
            }
            _ => panic!("{re} must be an assign statement"),
        }
    }

    #[test]
    fn anon_function_call() {
        assert!(matches!(result("a(1, 2, 3);").kind(), &Call(..)))
    }

    #[test]
    fn named_function_call() {
        assert!(matches!(
            result("script_tag(name:\"cvss_base\", value:1 + 1 % 2);").kind(),
            &Call(..)
        ));
    }
}
