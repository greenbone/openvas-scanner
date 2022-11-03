use std::{fmt, string::ParseError};

use crate::token::{self, Category, Token};

/// Parses given statements containing numeric Operator to order the precedence.
///
/// NASL does only contain precedence operator on numeric values all other operator do just
/// contain a left and right operation that can be interprete in sequence while 1 + 5 * 6 cannot.
/// Therefore we need to transform those statements:
/// 1 + 5 * 6 => ( + 1 ( * 5 6))
/// To simplify the interpreter later on.
///

struct Lexer<'a> {
    tokens: &'a mut Vec<Token>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Statement {
    Primitive(Token),
    Operator(token::Category, Vec<Statement>),
    // Logic
    //
    Variable(Token),
    Call(Token, Box<Statement>), // TODO maybe box
    Parameter(Vec<Statement>),
    // Function(Token, Vec<Token>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ParseErr<'a> {
    reason: &'a str,
    position: (usize, usize),
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
            | Category::StarStar => Some(Operator::Operator(token.category())),
            Category::String(_) | Category::Number(_) => Some(Operator::Primitive(token)),
            Category::LeftParen | Category::Comma => Some(Operator::Grouping(token.category())),
            Category::Identifier(_) => Some(Operator::Variable(token)),
            _ => None,
        }
    }
}

fn prefix_binding_power<'a>(token: Token) -> Result<u8, ParseErr<'a>> {
    match token.category() {
        token::Category::Plus | token::Category::Minus => Ok(9),
        _ => Err(ParseErr {
            reason: "Bad operation",
            position: token.position,
        }),
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
    pub fn new(tokens: &mut Vec<Token>) -> Lexer {
        tokens.reverse();
        Lexer { tokens }
    }

    fn next(&mut self) -> Option<Token> {
        self.tokens.pop()
    }
    fn peek(&self) -> Option<Token> {
        self.tokens.last().copied()
    }

    pub fn expression(&mut self) -> Result<Statement, ParseErr<'a>> {
        self.expression_bp(0)
    }

    fn prefix_statement(&mut self) -> Result<Statement, ParseErr<'a>> {
        let token = self.next().map(Ok).unwrap_or(Err(ParseErr {
            reason: "Insufficient statements",
            position: (0, 0),
        }))?;
        let op = Operator::new(token).map(Ok).unwrap_or(Err(ParseErr {
            reason: "Unknown operator",
            position: token.position,
        }))?;
        match op {
            Operator::Operator(kind) => {
                let bp = prefix_binding_power(token)?;
                let rhs = self.expression_bp(bp)?;
                Ok(Statement::Operator(kind, vec![rhs]))
            }
            Operator::Primitive(token) => Ok(Statement::Primitive(token)),
            Operator::Variable(token) => match self.peek() {
                Some(x) if x.category() == Category::LeftParen => {
                    self.next();
                    let parameter = self.parse_paren(x)?;
                    Ok(Statement::Call(token, Box::new(parameter)))
                }

                _ => Ok(Statement::Variable(token)),
            },
            Operator::Grouping(category) if category == Category::LeftParen => {
                self.parse_paren(token)
            }
            Operator::Grouping(_) => Err(ParseErr {
                reason: "Unknown grouping",
                position: token.position,
            }),
        }
    }

    fn expression_bp(&mut self, min_bp: u8) -> Result<Statement, ParseErr<'a>> {
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
                _ => Err(ParseErr {
                    reason: "Wrong Operator",
                    position: token.position,
                }),
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

    fn parse_paren(&mut self, token: Token) -> Result<Statement, ParseErr<'a>> {
        let lhs = self.expression_bp(0)?;
        if let Some(peeked) = self.peek() {
            if peeked.category() != Category::RightParen {
                return Err(ParseErr {
                    reason: "Unclosed parent",
                    position: peeked.position,
                });
            } else {
                self.next();
                return Ok(lhs);
            }
        }
        Err(ParseErr {
            reason: "Unclosed parent",
            position: token.position,
        })
    }

    fn postfix_statement(
        &mut self,
        token: Token,
        lhs: Statement,
    ) -> Result<Statement, ParseErr<'a>> {
        self.next();
        match token.category() {
            Category::Comma => {
                let mut lhs = match lhs {
                    Statement::Parameter(x) => x,
                    x => vec![x],
                };
                match self.expression_bp(0)? {
                    Statement::Parameter(mut x) => lhs.append(&mut x),
                    x => lhs.push(x),
                };
                // flatten parameer
                Ok(Statement::Parameter(lhs))
            }
            _ => Err(ParseErr {
                reason: "Unknown postfix operator",
                position: token.position,
            }),
        }
    }
}

fn postfix_binding_power(category: Category) -> Option<u8> {
    let res = match category {
        Category::Comma => 9,
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
        let callable = |mut stmts: Vec<Statement>, calulus: Box<dyn Fn(i64, i64) -> i64>| -> i64 {
            let right = stmts.pop().unwrap();
            let left = stmts.pop().unwrap();
            calulus(
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
            Call(_, _) => todo!(),
            Parameter(_) => todo!(),
        }
    }

    fn token(category: token::Category, start: usize, end: usize) -> Token {
        Token {
            category,
            position: (start, end),
        }
    }

    macro_rules! expression {
        ($code:expr) => {{
            let mut tokens = Tokenizer::new($code).collect::<Vec<Token>>();
            let mut parser = Lexer::new(&mut tokens);
            match parser.expression() {
                Ok(stmt) => stmt,
                Err(p) => {
                    let (start, end) = p.position;
                    panic!(
                        "{}: `{}` {:?}",
                        p.reason,
                        &$code[Range { start, end }],
                        p.position
                    );
                }
            }
        }};
    }

    macro_rules! calculated_test {
        ($code:expr, $expected:expr) => {
            let variables = [("a", 1)];
            let expr = expression!($code);
            assert_eq!(resolve(&variables, $code, expr), $expected);
        };
    }
    #[test]
    fn single_statement() {
        assert_eq!(expression!("1"), Primitive(token(Number(Base10), 0, 1)));
        assert_eq!(
            expression!("'a'"),
            Primitive(token(String(token::StringCategory::Quoteable), 1, 2))
        );
        assert_eq!(expression!("a"), Variable(token(Identifier(None), 0, 1)));
        let fn_name = token(Identifier(None), 0, 1);
        let args = Box::new(Parameter(vec![
            Primitive(token(Number(Base10), 2, 3)),
            Primitive(token(Number(Base10), 5, 6)),
            Primitive(token(Number(Base10), 8, 9)),
        ]));

        assert_eq!(expression!("a(1, 2, 3)"), Call(fn_name, args));
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
}
