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
                    let right = b.map(|x| i32::from(&x)).unwrap_or_default();
                    Ok(NaslValue::Number(i32::from(&left) - right))
                }
            }),
            // number
            TokenCategory::Star => todo!(),
            TokenCategory::Slash => todo!(),
            TokenCategory::Percent => todo!(),
            TokenCategory::LessLess => todo!(),
            TokenCategory::GreaterGreater => todo!(),
            TokenCategory::GreaterGreaterGreater => todo!(),
            TokenCategory::Ampersand => todo!(),
            TokenCategory::Pipe => todo!(),
            TokenCategory::Caret => todo!(),
            TokenCategory::StarStar => todo!(),
            TokenCategory::Tilde => todo!(),
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
        let code = $code;
        let storage = DefaultSink::new(false);
        let mut interpreter = Interpreter::new(&storage, vec![], Some("1"), None, code);
        let mut parser = parse(code).map(|x| match x {
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
            string_minus : "'hello ' - 'o ';" => NaslValue::String("hell".to_owned())
    }
}
