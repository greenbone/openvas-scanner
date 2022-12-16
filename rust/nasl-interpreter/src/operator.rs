use nasl_syntax::{Statement, TokenCategory};

use crate::{error::InterpretError, interpreter::InterpretResult, Interpreter, NaslValue};

/// Is a trait to handle operator within nasl.
pub(crate) trait OperatorExtension {
    /// Returns result of an operator
    fn operator(&mut self, category: TokenCategory, stmts: Vec<Statement>) -> InterpretResult;
}

impl<'a> Interpreter<'a> {
    #[inline(always)]
    fn execute(
        &mut self,
        mut stmts: Vec<Statement>,
        result: impl Fn(NaslValue, Option<NaslValue>) -> InterpretResult,
    ) -> InterpretResult {
        // operation on no values
        if stmts.is_empty() {
            return Err(InterpretError {
                reason: "".to_owned(),
            });
        }
        // operation on more than two values
        if stmts.len() > 2 {
            return Err(InterpretError {
                reason: "".to_owned(),
            });
        }
        let (left, right) = {
            let last = self.resolve(stmts.pop().unwrap())?;
            let second = stmts.pop().map(|x| self.resolve(x));
            match second {
                None => (last, None),
                Some(Ok(x)) => (x, Some(last)),
                Some(Err(err)) => return Err(err),
            }
        };
        result(left, right)
    }
}

#[inline(always)]
fn as_i32(left: NaslValue, right: Option<NaslValue>) -> (i32, i32) {
    (
        i32::from(&left),
        right.map(|x| i32::from(&x)).unwrap_or_default(),
    )
}

macro_rules! expr {
    ($e:expr) => {
        $e
    };
}
macro_rules! num_expr {
    ($op:tt $left:ident $right:ident) => {
        {
        let (left, right) = as_i32($left, $right);
        let result = expr!(left $op right);
        Ok(NaslValue::Number(result))
        }
    };
    ($op:expr => $left:ident $right:ident) => {
        {
        let (left, right) = as_i32($left, $right);
        let result = $op(left, right);
        Ok(NaslValue::Number(result))
        }
    };
}

impl<'a> OperatorExtension for Interpreter<'a> {
    fn operator(&mut self, category: TokenCategory, stmts: Vec<Statement>) -> InterpretResult {
        match category {
            // number and string
            TokenCategory::Plus => self.execute(stmts, |a, b| match a {
                NaslValue::String(x) => {
                    let right = b.map(|x| x.to_string()).unwrap_or_default();
                    Ok(NaslValue::String(format!("{}{}", x, right)))
                }
                left => {
                    let right = b.map(|x| i32::from(&x)).unwrap_or_default();
                    Ok(NaslValue::Number(i32::from(&left) + right))
                }
            }),
            TokenCategory::Minus => self.execute(stmts, |a, b| match a {
                NaslValue::String(x) => {
                    let right: String = b.map(|x| x.to_string()).unwrap_or_default();
                    Ok(NaslValue::String(x.replacen(&right, "", 1)))
                }
                left => {
                    let result = match b {
                        Some(right) => {
                           i32::from(&left) - i32::from(&right)
                        }
                        None => -i32::from(&left)
                    };
                    Ok(NaslValue::Number(result))
                }
            }),
            // number
            TokenCategory::Star => self.execute(stmts, |a, b| num_expr!(* a b)),
            TokenCategory::Slash => self.execute(stmts, |a, b| num_expr!(/ a b)),
            TokenCategory::Percent => self.execute(stmts, |a, b| num_expr!(% a b)),
            TokenCategory::LessLess => self.execute(stmts, |a, b| num_expr!(|a, b| a << b => a b)),
            TokenCategory::GreaterGreater => {
                self.execute(stmts, |a, b| num_expr!(|a, b| a >> b => a b))
            }
            // let left_casted = left as u32; (left_casted >> right) as i64
            TokenCategory::GreaterGreaterGreater => {
                self.execute(stmts, |a, b| num_expr!(|a, b| ((a as u32) >> b) as i32 => a b))
            },
            TokenCategory::Ampersand => self.execute(stmts, |a, b| num_expr!(& a b)),
            TokenCategory::Pipe => self.execute(stmts, |a, b| num_expr!(| a b)),
            TokenCategory::Caret => self.execute(stmts, |a, b| num_expr!(^ a b)),
            TokenCategory::StarStar => {
                self.execute(stmts,|a, b| num_expr!(|a, b| (a as u32).pow(b as u32) as i32 => a b))
            }
            TokenCategory::Tilde => {
                self.execute(stmts,|a, b| num_expr!(|a: i32, _: i32| !a => a b))
            },
            // string
            TokenCategory::EqualTilde => todo!(),
            TokenCategory::BangTilde => todo!(),
            TokenCategory::GreaterLess => todo!(),
            TokenCategory::GreaterBangLess => todo!(),
            // bool
            TokenCategory::Bang => todo!(),
            TokenCategory::AmpersandAmpersand => todo!(),
            TokenCategory::PipePipe => todo!(),
            TokenCategory::EqualEqual => todo!(),
            TokenCategory::BangEqual => todo!(),
            TokenCategory::Greater => todo!(),
            TokenCategory::Less => todo!(),
            TokenCategory::GreaterEqual => todo!(),
            TokenCategory::LessEqual => todo!(),
            // weird
            TokenCategory::X => todo!(),
            _ => Err(InterpretError {
                reason: format!("Unsupported operations {:?}", category),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use nasl_syntax::parse;
    use sink::DefaultSink;

    use crate::{error::InterpretError, Interpreter, NaslValue};

    macro_rules! create_test {
        ($($name:tt: $code:expr => $result:expr),*) => {

        $(
            #[test]
            fn $name() {
                let storage = DefaultSink::new(false);
                let mut interpreter = Interpreter::new(&storage, vec![], Some("1"), None, $code);
                let mut parser = parse($code).map(|x| match x {
                    Ok(x) => interpreter.resolve(x),
                    Err(x) => Err(InterpretError {
                        reason: x.to_string(),
                    }),
                });
                assert_eq!(parser.next(), Some(Ok($result)));
            }
        )*
        };
    }
    create_test! {
        numeric_plus: "1+2;" => NaslValue::Number(3),
        string_plus: "'hello ' + 'world!';" => NaslValue::String("hello world!".to_owned()),
        numeric_minus : "1 - 2;" => NaslValue::Number(-1),
        string_minus : "'hello ' - 'o ';" => NaslValue::String("hell".to_owned()),
        multiplication: "1*2;" => NaslValue::Number(2),
        division: "512/2;" => NaslValue::Number(256),
        modulo: "512%2;" => NaslValue::Number(0),
        left_shift: "512 << 2;" => NaslValue::Number(2048),
        right_shift: "512 >> 2;" => NaslValue::Number(128),
        unsigned_right_shift: "-2 >>> 2;" => NaslValue::Number(1073741823),
        and: "-2 & 2;" => NaslValue::Number(2),
        or: "-2 | 2;" => NaslValue::Number(-2),
        xor: "-2 ^ 2;" => NaslValue::Number(-4),
        pow: "2 ** 2;" => NaslValue::Number(4),
        not: "~2;" => NaslValue::Number(-3)
    }
}
