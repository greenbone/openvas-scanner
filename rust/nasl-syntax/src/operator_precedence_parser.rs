use std::fmt;

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
    Atom(Token),
    Operation(token::Category, Vec<Statement>),
}

impl Statement {
    pub fn format(self, code: &str) -> String {
        match self {
            Self::Atom(i) => format!(" {} ", code[i.range()].to_owned()),
            Self::Operation(head, rest) => {
                let mut result = format!("({:?}", head);
                for s in rest {
                    result += &Statement::format(s, code);
                }
                result += ")";
                result
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ParseErr<'a> {
    reason: &'a str,
    position: (usize, usize),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Operator {
    Arithmetic(token::Category), // only allowed on numbers
    Grouping(token::Category),   // grouping operator ()

    Atom(Token), // not an operation
}

impl Operator {
    fn new(token: Token) -> Option<Operator> {
        match token.category() {
            Category::Plus
            | Category::Star
            | Category::Slash
            | Category::Minus 
            | Category::Percent // modulo 
            | Category::StarStar // pow 
                => Some(Operator::Arithmetic(token.category())),
            Category::Identifier(_) | Category::Number(_) => Some(Operator::Atom(token)),
            Category::LeftParen => Some(Operator::Grouping(token.category())),
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
        {
            if let Some(token) = self.next() {
                if let Some(op) = Operator::new(token) {
                    match op {
                        Operator::Arithmetic(kind) => {
                            let bp = prefix_binding_power(token)?;
                            let rhs = self.expression_bp(bp)?;
                            Ok(Statement::Operation(kind, vec![rhs]))
                        }
                        Operator::Atom(token) => Ok(Statement::Atom(token)),
                        Operator::Grouping(category) if category == Category::LeftParen => {
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
                        Operator::Grouping(_) => Err(ParseErr {
                            reason: "Unknown grouping",
                            position: token.position,
                        }),
                    }
                } else {
                    Err(ParseErr {
                        reason: "Unknown operator",
                        position: token.position,
                    })
                }
            } else {
                Err(ParseErr {
                    reason: "Insufficient statements",
                    position: (0, 0),
                })
            }
        }
    }

    fn expression_bp(&mut self, min_bp: u8) -> Result<Statement, ParseErr<'a>> {
        let mut lhs = self.prefix_statement()?;
        loop {
            let token = match self.peek() {
                Some(t) => t,
                None => break,
            };
            match Operator::new(token) {
                Some(op) => {
                    let guarded = match op {
                        Operator::Arithmetic(category) => Ok(category),
                        _ => Err(ParseErr {
                            reason: "Unknown Operator",
                            position: token.position,
                        }),
                    }?;
                    // we skip postifx for now
                    if let Some((l_bp, r_bp)) = infix_binding_power(guarded) {
                        if l_bp < min_bp {
                            break;
                        }
                        self.next();
                        lhs = {
                            let rhs = self.expression_bp(r_bp)?;
                            Statement::Operation(token.category(), vec![lhs, rhs])
                        }
                    }
                }
                None => break,
            }
        }
        Ok(lhs)
    }
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
    use Statement::*;

    // simplified resolve method to verify a calculate with a given statement
    fn resolve(code: &str, s: Statement) -> i64 {
        let callable = |mut stmts: Vec<Statement>, calulus: Box<dyn Fn(i64, i64) -> i64>| -> i64 {
            let right = stmts.pop().unwrap();
            let left = stmts.pop().unwrap();
            calulus(resolve(code, left), resolve(code, right))
        };
        match s {
            Atom(token) => match token.category() {
                Number(_) => code[token.range()].parse().unwrap(),
                Identifier(_) => 1,
                _ => 0,
            },
            Operation(head, rest) => match head {
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
        }
    }

    macro_rules! calculated_test {
        ($code:expr, $expected:expr) => {
            let mut tokenizer = Tokenizer::new($code).collect::<Vec<Token>>();
            let mut parser = Lexer::new(&mut tokenizer);
            let expr = parser.expression().unwrap();
            assert_eq!(resolve($code, expr), $expected);
        };
    }
    #[test]
    fn single_statement() {
        calculated_test!("1", 1);
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
