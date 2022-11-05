use crate::{
    assign_operator_extension::AssignOperator,
    keyword_extension::Keywords,
    parser::{AssignCategory, Statement, TokenError},
    postifx_extension::Postfix,
    token::{self, Category, Keyword, Token, Tokenizer},
    variable_extension::Variables,
};

/// Parses given statements containing numeric Operator to order the precedence.
///
/// NASL does only contain precedence operator on numeric values all other operator do just
/// contain a left and right operation that can be interprete in sequence while 1 + 5 * 6 cannot.
/// Therefore we need to transform those statements:
/// 1 + 5 * 6 => ( + 1 ( * 5 6))
/// To simplify the interpreter later on.
///

pub(crate) struct Lexer<'a> {
    tokenizer: Tokenizer<'a>,
    pub(crate) previous_token: Option<Token>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Operator {
    Operator(token::Category),
    AssignOperator(token::Category, token::Category, u8),
    Assign(token::Category),
    Grouping(token::Category), // grouping operator ()
    Variable(Token),           // not an operation
    Primitive(Token),
    Keyword(Keyword), // not an operation
}

impl Operator {
    fn new(token: Token) -> Option<Operator> {
        match token.category() {
            Category::Plus
            | Category::Star
            | Category::Slash
            | Category::Minus
            | Category::Percent
            | Category::StarStar => Some(Operator::Operator(token.category())),
            Category::PlusPlus => Some(Operator::AssignOperator(
                Category::PlusPlus,
                Category::Plus,
                1,
            )),
            Category::MinusMinus => Some(Operator::AssignOperator(
                Category::MinusMinus,
                Category::Minus,
                1,
            )),
            Category::Equal => Some(Operator::Assign(Category::Equal)),
            Category::String(_) | Category::Number(_) => Some(Operator::Primitive(token)),
            Category::LeftParen | Category::Comma => Some(Operator::Grouping(token.category())),
            Category::Identifier(None) => Some(Operator::Variable(token)),
            Category::Identifier(Some(keyword)) => Some(Operator::Keyword(keyword)),
            _ => None,
        }
    }
}

fn prefix_binding_power(token: Token) -> Result<u8, TokenError> {
    match token.category() {
        token::Category::Plus | token::Category::Minus => Ok(9),
        _ => Err(TokenError::unexpected_token(token)),
    }
}

impl<'a> Lexer<'a> {
    /// Creates a new Pratt Lexer
    ///
    /// It assumes that the caller gives already a list of Tokens.
    /// Before cerating a the Parser new does reverse the given list.
    //
    /// Depending on the context it cannot determine the end condition for a statement.
    /// E.g. when is it is in a if statement the end condition is the ) matching the root level
    /// while on a assign exprresion a = 1 + 5 * 6; it is a semicolon.
    //
    /// This Parser only intention is to order operator therefore we rely on the caller
    /// to verify if a macthing Operator is in that statement.
    fn new(tokenizer: Tokenizer<'a>) -> Lexer<'a> {
        Lexer {
            tokenizer,
            previous_token: None,
        }
    }

    pub(crate) fn next(&mut self) -> Option<Token> {
        self.tokenizer.next()
    }

    /// Handles statements before operation statements get handled.
    /// This is mostly done to detect statements that should not be weighted and executed before hand
    fn prefix_statement(&mut self, token: Token, abort: Category) -> Result<Statement, TokenError> {
        let op = Operator::new(token).ok_or_else(|| TokenError::unexpected_token(token))?;
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

    pub(crate) fn expression_bp(
        &mut self,
        min_bp: u8,
        abort: Category,
    ) -> Result<Statement, TokenError> {
        let token = self
            .previous_token
            .or_else(|| self.next())
            .ok_or_else(|| TokenError::unexpected_end("parsing prefix statement"))?;
        if token.category() == abort {
            return Ok(Statement::NoOp(Some(token)));
        }

        let mut lhs = self.prefix_statement(token, abort)?;
        loop {
            let token = {
                let r = match self.previous_token {
                    None => self.next(),
                    x => {
                        self.previous_token = None;
                        x
                    }
                };
                match r {
                    Some(x) => x,
                    None => break,
                }
            };
            if token.category() == abort {
                self.previous_token = Some(token);
                break;
            }
            let op = {
                match Operator::new(token) {
                    Some(op) => match op {
                        Operator::Operator(_)
                        | Operator::Assign(_)
                        | Operator::Grouping(_)
                        | Operator::AssignOperator(_, _, _) => Ok(op),
                        _ => Err(TokenError::unexpected_token(token)),
                    },
                    None => break,
                }
            }?;

            if self.needs_postfix(op) {
                let stmt = self
                    .postfix_statement(op, token, lhs, abort)
                    .expect("needs postfix should have been validated before")?;
                lhs = stmt;
                continue;
            }

            if let Some((l_bp, r_bp)) = infix_binding_power(op) {
                if l_bp < min_bp {
                    self.previous_token = Some(token);
                    break;
                }
                lhs = {
                    let rhs = self.expression_bp(r_bp, abort)?;
                    match op {
                        // Assign needs to be translated due handle the return cases for e.g. ( a = 1) * 2
                        Operator::Assign(_) => match lhs {
                            Statement::Variable(token) => {
                                Statement::Assign(AssignCategory::Assign, token, Box::new(rhs))
                            }
                            _ => Statement::Operator(token.category(), vec![lhs, rhs]),
                        },
                        _ => Statement::Operator(token.category(), vec![lhs, rhs]),
                    }
                }
            }
        }

        Ok(lhs)
    }

    pub(crate) fn parse_paren(&mut self, token: Token) -> Result<Statement, TokenError> {
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

fn infix_binding_power(op: Operator) -> Option<(u8, u8)> {
    use self::Operator::*;
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

pub fn expression<'a>(tokenizer: Tokenizer<'a>) -> Result<Statement, TokenError> {
    //let tokenizer = Tokenizer::new(code);
    let mut lexer = Lexer::new(tokenizer);
    let init = lexer.expression_bp(0, Category::Semicolon)?;
    Ok(init)
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::token::Base::*;
    use crate::token::Category::*;
    use crate::token::StringCategory;
    use crate::token::{Token, Tokenizer};
    use Statement::*;

    fn string_hasher(input: &str) -> i64 {
        let mut hash: u64 = 0;
        for b in input.bytes() {
            hash = b as u64 + (hash << 6) + (hash << 16) - hash;
        }
        hash as i64
    }

    // simplified resolve method to verify a calculate with a given statement
    fn resolve(variables: &[(&str, i32)], code: &str, s: Statement) -> i64 {
        let callable = |mut stmts: Vec<Statement>, calculus: Box<dyn Fn(i64, i64) -> i64>| -> i64 {
            let right = stmts.pop().unwrap();
            let left = stmts.pop().unwrap();
            calculus(
                resolve(variables, code, left),
                resolve(variables, code, right),
            )
        };
        match s {
            Primitive(token) => match token.category() {
                Number(_) => code[token.range()].parse().unwrap(),
                String(_) => string_hasher(&code[token.range()]),
                _ => 0,
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
                _ => -42,
            },
            Variable(token) => {
                let wanted = &code[token.range()];
                for (id, val) in variables {
                    if id == &wanted {
                        return *val as i64;
                    }
                }
                -1
            }
            _ => todo!(),
        }
    }

    fn token(category: token::Category, start: usize, end: usize) -> Token {
        Token {
            category,
            position: (start, end),
        }
    }

    macro_rules! expression_test {
        ($code:expr, $expected:expr) => {{
            let tokenizer = Tokenizer::new($code);
            let actual = expression(tokenizer).unwrap();
            assert_eq!(actual, $expected);
        }};
    }

    macro_rules! calculated_test {
        ($code:expr, $expected:expr) => {
            let tokenizer = Tokenizer::new($code);
            let variables = [("a", 1)];
            let expr = expression(tokenizer).unwrap();
            assert_eq!(resolve(&variables, $code, expr), $expected);
        };
    }
    #[test]
    fn single_statement() {
        expression_test!("1", Primitive(token(Number(Base10), 0, 1)));
        expression_test!(
            "'a'",
            Primitive(token(String(token::StringCategory::Quoteable), 1, 2))
        );

        expression_test!("a", Variable(token(Identifier(None), 0, 1)));
        let fn_name = token(Identifier(None), 0, 1);
        let args = Box::new(Parameter(vec![
            Primitive(token(Number(Base10), 2, 3)),
            Primitive(token(Number(Base10), 5, 6)),
            Primitive(token(Number(Base10), 8, 9)),
        ]));

        expression_test!("a(1, 2, 3)", Call(fn_name, args));
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
        expression_test!(
            "a = 1",
            Assign(
                AssignCategory::Assign,
                token(Identifier(None), 0, 1),
                Box::new(Primitive(Token {
                    category: Number(Base10),
                    position: (4, 5)
                }))
            )
        );
        expression_test!(
            "(a = 1)",
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
