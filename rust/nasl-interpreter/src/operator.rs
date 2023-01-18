use nasl_syntax::{Statement, TokenCategory};
use regex::Regex;

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
            return Err(InterpretError::new(
                "Internal error: operation without statements is invalid.".to_string(),
            ));
        }
        // operation on more than two values
        if stmts.len() > 2 {
            return Err(InterpretError::internal_error(
                &stmts[0],
                &"operation with more than two statements is invalid.".to_string(),
            ));
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
fn as_i64(left: NaslValue, right: Option<NaslValue>) -> (i64, i64) {
    (
        i64::from(&left),
        right.map(|x| i64::from(&x)).unwrap_or_default(),
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
        let (left, right) = as_i64($left, $right);
        let result = expr!(left $op right);
        Ok(NaslValue::Number(result as i64))
        }
    };
    ($op:expr => $left:ident $right:ident) => {
        {
        let (left, right) = as_i64($left, $right);
        let result = $op(left, right);
        Ok(NaslValue::Number(result as i64))
        }
    };
}

fn match_regex(a: NaslValue, matches: Option<NaslValue>) -> InterpretResult {
    let right = matches.map(|x| x.to_string()).unwrap_or_default();
    match Regex::new(&right) {
        Ok(c) => Ok(NaslValue::Boolean(c.is_match(&a.to_string()))),
        Err(err) => Err(InterpretError::new(format!(
            "{} is a invalid regex: {}.",
            right, err
        ))),
    }
}

fn not_match_regex(a: NaslValue, matches: Option<NaslValue>) -> InterpretResult {
    let result = match_regex(a, matches)?;
    Ok(NaslValue::Boolean(!bool::from(result)))
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
                    let right = b.map(|x| i64::from(&x)).unwrap_or_default();
                    Ok(NaslValue::Number(i64::from(&left) + right))
                }
            }),
            TokenCategory::Minus => self.execute(stmts, |a, b| match a {
                NaslValue::String(x) => {
                    let right: String = b.map(|x| x.to_string()).unwrap_or_default();
                    Ok(NaslValue::String(x.replacen(&right, "", 1)))
                }
                left => {
                    let result = match b {
                        Some(right) => i64::from(&left) - i64::from(&right),
                        None => -i64::from(&left),
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
            TokenCategory::GreaterGreaterGreater => self.execute(
                stmts,
                |a, b| num_expr!(|a, b| ((a as u32) >> b) as i32 => a b),
            ),
            TokenCategory::Ampersand => self.execute(stmts, |a, b| num_expr!(& a b)),
            TokenCategory::Pipe => self.execute(stmts, |a, b| num_expr!(| a b)),
            TokenCategory::Caret => self.execute(stmts, |a, b| num_expr!(^ a b)),
            TokenCategory::StarStar => self.execute(
                stmts,
                |a, b| num_expr!(|a, b| (a as u32).pow(b as u32) as i32 => a b),
            ),
            TokenCategory::Tilde => {
                self.execute(stmts, |a, b| num_expr!(|a: i64, _: i64| !a => a b))
            }
            // string
            TokenCategory::EqualTilde => self.execute(stmts, match_regex),
            TokenCategory::BangTilde => self.execute(stmts, not_match_regex),
            TokenCategory::GreaterLess => self.execute(stmts, |a, b| {
                let substr = b.map(|x| x.to_string()).unwrap_or_default();
                Ok(NaslValue::Boolean(a.to_string().contains(&substr)))
            }),
            TokenCategory::GreaterBangLess => self.execute(stmts, |a, b| {
                let substr = b.map(|x| x.to_string()).unwrap_or_default();
                Ok(NaslValue::Boolean(!a.to_string().contains(&substr)))
            }),
            // bool
            TokenCategory::Bang => {
                self.execute(stmts, |a, _| Ok(NaslValue::Boolean(!bool::from(a))))
            }
            TokenCategory::AmpersandAmpersand => self.execute(stmts, |a, b| {
                let right = b.map(bool::from).unwrap_or_default();
                Ok(NaslValue::Boolean(bool::from(a) && right))
            }),
            TokenCategory::PipePipe => self.execute(stmts, |a, b| {
                let right = b.map(bool::from).unwrap_or_default();
                Ok(NaslValue::Boolean(bool::from(a) || right))
            }),
            TokenCategory::EqualEqual => self.execute(stmts, |a, b| {
                let right = b.unwrap_or(NaslValue::Null);
                Ok(NaslValue::Boolean(a == right))
            }),
            TokenCategory::BangEqual => self.execute(stmts, |a, b| {
                let right = b.unwrap_or(NaslValue::Null);
                Ok(NaslValue::Boolean(a != right))
            }),
            TokenCategory::Greater => self.execute(stmts, |a, b| {
                let right = b.map(|x| i64::from(&x)).unwrap_or_default();
                Ok(NaslValue::Boolean(i64::from(&a) > right))
            }),
            TokenCategory::Less => self.execute(stmts, |a, b| {
                let right = b.map(|x| i64::from(&x)).unwrap_or_default();
                Ok(NaslValue::Boolean(i64::from(&a) < right))
            }),
            TokenCategory::GreaterEqual => self.execute(stmts, |a, b| {
                let right = b.map(|x| i64::from(&x)).unwrap_or_default();
                Ok(NaslValue::Boolean(i64::from(&a) >= right))
            }),
            TokenCategory::LessEqual => self.execute(stmts, |a, b| {
                let right = b.map(|x| i64::from(&x)).unwrap_or_default();
                Ok(NaslValue::Boolean(i64::from(&a) <= right))
            }),
            TokenCategory::X => {
                // operation on more than two values
                if stmts.len() != 2 {
                    return Err(InterpretError::internal_error(
                        &stmts[0],
                        &format!("operation is invalid."),
                    ));
                }
                let mut stmts = stmts;
                let repeat = {
                    let last = self.resolve(stmts.pop().unwrap())?;
                    i64::from(&last)
                };
                if repeat == 0 {
                    // don't execute;
                    return Ok(NaslValue::Null);
                }
                let repeatable = stmts.pop().unwrap();
                for _ in 1..repeat - 1 {
                    self.resolve(repeatable.clone())?;
                }
                self.resolve(repeatable)
            }

            _ => Err(stmts
                .get(0)
                .map(|stmt| InterpretError::unsupported(stmt, "operation"))
                .unwrap_or_else(|| InterpretError::new(format!("Internal error: missing stmts")))),
        }
    }
}

#[cfg(test)]
mod tests {
    use nasl_syntax::parse;
    use sink::DefaultSink;

    use crate::{Interpreter, NaslValue};
    use crate::{NoOpLoader, Register};

    macro_rules! create_test {
        ($($name:tt: $code:expr => $result:expr),*) => {

        $(
            #[test]
            fn $name() {
                let storage = DefaultSink::new(false);
                let mut register = Register::default();
                let loader = NoOpLoader::default();
                let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
                let mut parser = parse($code).map(|x|
                    interpreter.resolve(x.expect("unexpected parse error"))
                );
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
        not: "~2;" => NaslValue::Number(-3),
        r_match: "'hello' =~ 'hell';" => NaslValue::Boolean(true),
        r_not_match: "'hello' !~ 'hell';" => NaslValue::Boolean(false),
        contains: "'hello' >< 'hell';" => NaslValue::Boolean(true),
        not_contains: "'hello' >!< 'hell';" => NaslValue::Boolean(false),
        bool_not: "!23;" => NaslValue::Boolean(false),
        bool_not_reverse: "!0;" => NaslValue::Boolean(true),
        bool_and: "1 && 1;" => NaslValue::Boolean(true),
        bool_or: "1 || 0;" => NaslValue::Boolean(true),
        equals_string: "'1' == '1';" => NaslValue::Boolean(true),
        equals_number: "1 == 1;" => NaslValue::Boolean(true),
        unequal: "1 != 1;" => NaslValue::Boolean(false),
        greater: "1 > 0;" => NaslValue::Boolean(true),
        less: "1 < 2;" => NaslValue::Boolean(true),
        greater_equal: "1 >= 1;" => NaslValue::Boolean(true),
        less_equal: "1 <= 1;" => NaslValue::Boolean(true),
        gonna_give_it_to_ya: "script_oid('hi') x 200;" => NaslValue::Null
    }
}
