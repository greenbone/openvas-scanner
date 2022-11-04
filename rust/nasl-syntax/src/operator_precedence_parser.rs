use crate::{
    parser::{Statement, TokenError},
    token::{self, Category, Token},
};

/// Parses given statements containing numeric Operator to order the precedence.
///
/// NASL does only contain precedence operator on numeric values all other operator do just
/// contain a left and right operation that can be interprete in sequence while 1 + 5 * 6 cannot.
/// Therefore we need to transform those statements:
/// 1 + 5 * 6 => ( + 1 ( * 5 6))
/// To simplify the interpreter later on.
///

struct Lexer<'a> {
    tokens: Vec<Token>,
    append_stmts: Vec<Statement<'a>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Operator {
    Operator(token::Category), // only allowed on numbers
    Grouping(token::Category), // grouping operator ()
    Variable(Token),           // not an operation
    Primitive(Token),          // not an operation
}

impl Operator {
    fn new(token: Token) -> Option<Operator> {
        match token.category() {
            Category::Plus
            | Category::Star
            | Category::Slash
            | Category::Minus
            | Category::Percent
            | Category::StarStar
            | Category::PlusPlus => Some(Operator::Operator(token.category())),
            Category::String(_) | Category::Number(_) => Some(Operator::Primitive(token)),
            Category::LeftParen | Category::Comma => Some(Operator::Grouping(token.category())),
            Category::Identifier(_) => Some(Operator::Variable(token)),
            _ => None,
        }
    }
}

fn prefix_binding_power<'a>(token: Token) -> Result<u8, TokenError> {
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
    fn new(mut tokens: Vec<Token>) -> Lexer<'a> {
        tokens.reverse();
        Lexer {
            tokens,
            append_stmts: vec![],
        }
    }

    fn next(&mut self) -> Option<Token> {
        self.tokens.pop()
    }
    // TODO remove the need for peek so that it can directly work with Tokenizer
    // and doesn't need reverse anymore and can be used as general parser instead of parser.rs
    fn peek(&self) -> Option<Token> {
        self.tokens.last().copied()
    }

    fn parse_variable(&mut self, token: Token) -> Result<Statement<'a>, TokenError> {
        if token.category() != Category::Identifier(None) {
            return Err(TokenError::unexpected_token(token));
        }
        match self.peek() {
            Some(x) if x.category() == Category::LeftParen => {
                self.next();
                let parameter = self.parse_paren(x)?;
                Ok(Statement::Call(token, Box::new(parameter)))
            }

            _ => Ok(Statement::Variable(token)),
        }
    }

    /// Handles statements before operation statements get handled.
    /// This is mostly done to detect statements that should not be weighted and executed before hand
    fn prefix_statement(&mut self) -> Result<Statement<'a>, TokenError> {
        let token = self
            .next()
            .map(Ok)
            .unwrap_or_else(|| Err(TokenError::unexpected_end("parsing prefix statements")))?;
        let op = Operator::new(token)
            .map(Ok)
            .unwrap_or_else(|| Err(TokenError::unexpected_token(token)))?;
        match op {
            Operator::Operator(kind) => {
                // maybe move to own category
                if kind == Category::PlusPlus {
                    let next = self
                        .next()
                        .ok_or_else(|| TokenError::unexpected_end("parsing prefix statement"))?;
                    return match self.parse_variable(next)? {
                        Statement::Variable(value) => Ok(Statement::AssignReturn(
                            value,
                            Box::new(Statement::Operator(
                                Category::Plus,
                                vec![Statement::Variable(token), Statement::RawNumber(1)],
                            )),
                        )),
                        _ => Err(TokenError::unexpected_token(token)),
                    };
                }
                let bp = prefix_binding_power(token)?;
                let rhs = self.expression_bp(bp)?;
                Ok(Statement::Operator(kind, vec![rhs]))
            }
            Operator::Primitive(token) => Ok(Statement::Primitive(token)),
            Operator::Variable(token) => self.parse_variable(token),
            Operator::Grouping(category) if category == Category::LeftParen => {
                self.parse_paren(token)
            }
            Operator::Grouping(_) => Err(TokenError::unexpected_token(token)),
        }
    }

    fn expression_bp(&mut self, min_bp: u8) -> Result<Statement<'a>, TokenError> {
        let mut lhs = self.prefix_statement()?;
        while let Some(token) = self.peek() {
            let op = {
                match Operator::new(token) {
                    Some(x) => x,
                    None => break,
                }
            };
            let guarded = match op {
                Operator::Operator(category) => Ok(category),
                Operator::Grouping(category) => Ok(category),
                _ => Err(TokenError::unexpected_token(token)),
            }?;

            if let Some(pfbp) = postfix_binding_power(guarded) {
                if pfbp < min_bp {
                    break;
                }

                lhs = self.postfix_statement(token, lhs)?;
                continue;
            }

            if let Some((l_bp, r_bp)) = infix_binding_power(guarded) {
                if l_bp < min_bp {
                    break;
                }
                self.next();
                lhs = {
                    let rhs = self.expression_bp(r_bp)?;
                    Statement::Operator(token.category(), vec![lhs, rhs])
                }
            }
        }

        Ok(lhs)
    }

    fn parse_paren(&mut self, token: Token) -> Result<Statement<'a>, TokenError> {
        let lhs = self.expression_bp(0)?;
        if let Some(peeked) = self.peek() {
            if peeked.category() != Category::RightParen {
                return Err(TokenError::unclosed(token));
            } else {
                self.next();
                return Ok(lhs);
            }
        }
        Err(TokenError::unclosed(token))
    }

    fn postfix_statement(
        &mut self,
        token: Token,
        lhs: Statement<'a>,
    ) -> Result<Statement<'a>, TokenError> {
        self.next();
        match token.category() {
            Category::Comma => {
                // flatten parameer
                let mut lhs = match lhs {
                    Statement::Parameter(x) => x,
                    x => vec![x],
                };
                match self.expression_bp(0)? {
                    Statement::Parameter(mut x) => lhs.append(&mut x),
                    x => lhs.push(x),
                };
                Ok(Statement::Parameter(lhs))
            }
            Category::PlusPlus => match lhs {
                Statement::Variable(token) => {
                    self.append_stmts.push(Statement::Assign(
                        token,
                        Box::new(Statement::Operator(
                            Category::Plus,
                            vec![Statement::Variable(token), Statement::RawNumber(1)],
                        )),
                    ));
                    Ok(lhs)
                }
                _ => Err(TokenError::unexpected_token(token)),
            },
            _ => Err(TokenError::unexpected_token(token)),
        }
    }
}

fn postfix_binding_power(category: Category) -> Option<u8> {
    let res = match category {
        Category::Comma => 9,
        Category::PlusPlus => 9,
        _ => return None,
    };
    Some(res)
}

fn infix_binding_power(guarded: Category) -> Option<(u8, u8)> {
    let res = match guarded {
        Category::Plus | Category::Minus => (5, 6),
        Category::Star | Category::Slash | Category::Percent | Category::StarStar => (7, 8),
        _ => return None,
    };
    Some(res)
}

pub fn expression<'a>(tokens: Vec<Token>) -> Result<Statement<'a>, TokenError> {
    let mut lexer = Lexer::new(tokens);
    let mut init = lexer.expression_bp(0)?;

    for append in lexer.append_stmts {
        init = Statement::Expanded(Box::new(init), Box::new(append));
    }
    Ok(init)
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::token::Base::*;
    use crate::token::Category::*;
    use crate::token::{Token, Tokenizer};
    use std::ops::Range;
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
            let tokens = Tokenizer::new($code).collect::<Vec<Token>>();
            let actual = expression(tokens).unwrap();
            assert_eq!(actual, $expected);
        }};
    }

    macro_rules! calculated_test {
        ($code:expr, $expected:expr) => {
            let variables = [("a", 1)];
            let tokens = Tokenizer::new($code).collect::<Vec<Token>>();
            let expr = expression(tokens).unwrap();
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
    fn prefix_assignment_operator() {
        expression_test!(
            "1 + ++a * 1",
            Operator(
                Plus,
                vec![
                    Primitive(Token {
                        category: Number(Base10),
                        position: (0, 1)
                    }),
                    Operator(
                        Star,
                        vec![
                            AssignReturn(
                                Token {
                                    category: Identifier(None),
                                    position: (6, 7)
                                },
                                Box::new(Operator(
                                    Plus,
                                    vec![
                                        Variable(Token {
                                            category: PlusPlus,
                                            position: (4, 6)
                                        }),
                                        RawNumber(1)
                                    ]
                                ))
                            ),
                            Primitive(Token {
                                category: Number(Base10),
                                position: (10, 11)
                            })
                        ]
                    )
                ]
            )
        );
    }

    #[test]
    fn postfix_assignment_operator() {
        expression_test!(
            "1 + a++ * 1",
            Expanded(
                Box::new(Operator(
                    Plus,
                    vec![
                        Primitive(Token {
                            category: Number(Base10),
                            position: (0, 1)
                        }),
                        Operator(
                            Star,
                            vec![
                                Variable(Token {
                                    category: Identifier(None),
                                    position: (4, 5)
                                }),
                                Primitive(Token {
                                    category: Number(Base10),
                                    position: (10, 11)
                                })
                            ]
                        )
                    ]
                )),
                Box::new(Assign(
                    Token {
                        category: Identifier(None),
                        position: (4, 5)
                    },
                    Box::new(Operator(
                        Plus,
                        vec![
                            Variable(Token {
                                category: Identifier(None),
                                position: (4, 5)
                            }),
                            RawNumber(1)
                        ]
                    ))
                ))
            )
        );
    }
}
