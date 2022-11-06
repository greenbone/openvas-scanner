use crate::{
    parser::{AssignCategory, Statement, TokenError},
    token::{Category, Token}, operation::Operation, lexer::Lexer,
};
pub(crate) trait Infix {
    fn handle_infix(&self, op: Operation, min_bp: u8) -> Option<bool>;

    fn infix_statement(
        &mut self,
        op: Operation,
        token: Token,
        lhs: Statement,
        abort: Category,
    ) -> Result<Statement, TokenError>;
}

fn infix_binding_power(op: Operation) -> Option<(u8, u8)> {
    use self::Operation::*;
    let res = match op {
        Assign(Category::Equal) => (4, 5),
        Operator(Category::Plus | Category::Minus) => (5, 6),
        Operator(Category::Star | Category::Slash | Category::Percent | Category::StarStar) => {
            (7, 8)
        }
        _ => return None,
    };
    Some(res)
}
impl<'a> Infix for Lexer<'a> {
    fn infix_statement(
        &mut self,
        op: Operation,
        token: Token,
        lhs: Statement,
        abort: Category,
    ) -> Result<Statement, TokenError> {
        let (_, r_bp) = infix_binding_power(op).expect("handle_infix should be called first");
        Ok({
            let rhs = self.expression_bp(r_bp, abort)?;
            match op {
                // Assign needs to be translated due handle the return cases for e.g. ( a = 1) * 2
                Operation::Assign(_) => match lhs {
                    Statement::Variable(token) => {
                        Statement::Assign(AssignCategory::Assign, token, Box::new(rhs))
                    }
                    _ => Statement::Operator(token.category(), vec![lhs, rhs]),
                },
                _ => Statement::Operator(token.category(), vec![lhs, rhs]),
            }
        })
    }

    fn handle_infix(&self, op: Operation, min_bp: u8) -> Option<bool> {
        let (l_bp, _) = infix_binding_power(op)?;
        if l_bp < min_bp {
            Some(false)
        } else {
            Some(true)
        }
    }
}


#[cfg(test)]
mod test {

    use crate::lexer::expression;
    use super::*;
    use crate::token::Base::*;
    use crate::token::Category::*;
    use crate::token::{Token, Tokenizer};
    use Statement::*;

    // simplified resolve method to verify a calculate with a given statement
    fn resolve(code: &str, s: Statement) -> i64 {
        let callable = |mut stmts: Vec<Statement>, calculus: Box<dyn Fn(i64, i64) -> i64>| -> i64 {
            let right = stmts.pop().unwrap();
            let left = stmts.pop().unwrap();
            calculus(
                resolve(code, left),
                resolve(code, right),
            )
        };
        match s {
            Primitive(token) => match token.category() {
                Number(_) => code[token.range()].parse().unwrap(),
                String(_) => todo!(),
                _ => todo!(),
            },
            Operator(head, rest) => match head {
                Plus => callable(rest, Box::new(|left, right| left + right)),
                Star => callable(rest, Box::new(|left, right| left * right)),
                Slash => callable(rest, Box::new(|left, right| left / right)),
                Percent => callable(rest, Box::new(|left, right| left % right)),
                StarStar => callable(
                    rest,
                    Box::new(|left, right| (left as u32).pow(right as u32) as i64),
                ),
                _ => todo!(),
            },
            _ => todo!(),
        }
    }

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

    macro_rules! calculated_test {
        ($code:expr, $expected:expr) => {
            let tokenizer = Tokenizer::new($code);
            let expr = expression(tokenizer).unwrap();
            assert_eq!(resolve($code, expr), $expected);
        };
    }

    #[test]
    fn ordering() {
        calculated_test!("1 + 5 * 6", 31);
        calculated_test!("3 * 10 + 10 / 5", 32);
        calculated_test!("3 * 10 / 5", 6);
        calculated_test!("3 * 10 / 5 % 4", 2);
    }

    #[test]
    fn grouping() {
        calculated_test!("(2 + 5) * 2", 14);
    }

    #[test]
    fn pow() {
        calculated_test!("2 ** 4", 16);
    }

    #[test]
    fn assignment() {
        assert_eq!(
            result("a = 1"),
            Assign(
                AssignCategory::Assign,
                token(Identifier(None), 0, 1),
                Box::new(Primitive(Token {
                    category: Number(Base10),
                    position: (4, 5)
                }))
            )
        );
        assert_eq!(
            result("(a = 1)"),
            Assign(
                AssignCategory::AssignReturn,
                token(Identifier(None), 1, 2),
                Box::new(Primitive(Token {
                    category: Number(Base10),
                    position: (5, 6)
                }))
            )
        );
    }
}
