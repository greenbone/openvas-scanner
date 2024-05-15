// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use nasl_syntax::{Statement, TokenCategory};
use regex::Regex;

use crate::{error::InterpretError, interpreter::InterpretResult, Interpreter};

use nasl_syntax::NaslValue;

/// Is a trait to handle operator within nasl.
pub(crate) trait OperatorExtension {
    /// Returns result of an operator
    fn operator(&mut self, category: &TokenCategory, stmts: &[Statement]) -> InterpretResult;
}

impl<'a, K> Interpreter<'a, K>
where
    K: AsRef<str>,
{
    fn execute(
        &mut self,
        stmts: &[Statement],
        result: impl Fn(NaslValue, Option<NaslValue>) -> InterpretResult,
    ) -> InterpretResult {
        // neither empty statements nor statements over 2 arguments should ever happen
        // because it is handled as a SyntaxError. Therefore we don't double check and
        // and let it run into a index out of bound panic to immediately escalate.
        let (left, right) = {
            let first = self.resolve(&stmts[0])?;
            if stmts.len() == 1 {
                (first, None)
            } else {
                (first, Some(self.resolve(&stmts[1])?))
            }
        };
        result(left, right)
    }
}

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
        Err(_) => Err(InterpretError::unparse_regex(&right)),
    }
}

fn not_match_regex(a: NaslValue, matches: Option<NaslValue>) -> InterpretResult {
    let result = match_regex(a, matches)?;
    Ok(NaslValue::Boolean(!bool::from(result)))
}

macro_rules! add_left_right_string {
    ($left: ident, $right:ident) => {{
        let right = $right.map(|x| x.to_string()).unwrap_or_default();
        let x = $left;
        Ok(NaslValue::String(format!("{x}{right}")))
    }};
}

macro_rules! minus_left_right_string {
    ($left: ident, $right:ident) => {{
        let right = $right.map(|x| x.to_string()).unwrap_or_default();
        let x = $left.to_string();
        Ok(NaslValue::String(x.replacen(&right, "", 1)))
    }};
}

macro_rules! add_left_right_data {
    ($left: ident, $right:ident) => {{
        let right = $right.map(|x| x.to_string()).unwrap_or_default();
        let x: Vec<u8> = $left.into();
        let x: String = x.into_iter().map(|b| b as char).collect();
        Ok(NaslValue::Data(format!("{x}{right}").into()))
    }};
}

macro_rules! minus_left_right_data {
    ($left: ident, $right:ident) => {{
        let right = $right.map(|x| x.to_string()).unwrap_or_default();
        let x: Vec<u8> = $left.into();
        let x: String = x.into_iter().map(|b| b as char).collect();
        Ok(NaslValue::Data(x.replacen(&right, "", 1).into()))
    }};
}

impl<'a, K> OperatorExtension for Interpreter<'a, K>
where
    K: AsRef<str>,
{
    fn operator(&mut self, category: &TokenCategory, stmts: &[Statement]) -> InterpretResult {
        match category {
            // number and string
            TokenCategory::Plus => self.execute(stmts, |a, b| match a {
                NaslValue::String(x) => add_left_right_string!(x, b),
                NaslValue::Data(x) => add_left_right_data!(x, b),
                left => match b {
                    Some(NaslValue::String(_)) => add_left_right_string!(left, b),
                    Some(NaslValue::Data(_)) => add_left_right_data!(left, b),
                    _ => {
                        let right = b.map(|x| i64::from(&x)).unwrap_or_default();
                        Ok(NaslValue::Number(i64::from(&left) + right))
                    }
                },
            }),
            TokenCategory::Minus => self.execute(stmts, |a, b| match a {
                NaslValue::String(x) => minus_left_right_string!(x, b),
                NaslValue::Data(x) => minus_left_right_data!(x, b),
                left => match b {
                    Some(NaslValue::String(_)) => minus_left_right_string!(left, b),
                    Some(NaslValue::Data(_)) => minus_left_right_data!(left, b),
                    _ => {
                        let result = match b {
                            Some(right) => i64::from(&left) - i64::from(&right),
                            None => -i64::from(&left),
                        };
                        Ok(NaslValue::Number(result))
                    }
                },
            }),
            // number
            TokenCategory::Star => self.execute(stmts, |a, b| num_expr!(* a b)),
            TokenCategory::Slash => self.execute(stmts, |a, b| num_expr!(/ a b)),
            TokenCategory::Percent => self.execute(stmts, |a, b| num_expr!(% a b)),
            TokenCategory::LessLess => self.execute(stmts, |a, b| num_expr!(<< a b)),
            TokenCategory::GreaterGreater => self.execute(stmts, |a, b| num_expr!(>> a b)),
            // let left_casted = left as u32; (left_casted >> right) as i64
            TokenCategory::GreaterGreaterGreater => self.execute(
                stmts,
                //|a, b| num_expr!(|a, b| ((a as u32) >> b) as i32 => a b),
                |a, b| {
                    let (left, right) = as_i64(a, b);
                    let result = ((left as u32) >> right) as i32;
                    Ok(NaslValue::Number(result as i64))
                },
            ),
            TokenCategory::Ampersand => self.execute(stmts, |a, b| num_expr!(& a b)),
            TokenCategory::Pipe => self.execute(stmts, |a, b| num_expr!(| a b)),
            TokenCategory::Caret => self.execute(stmts, |a, b| num_expr!(^ a b)),
            TokenCategory::StarStar => self.execute(stmts, |a, b| {
                let (a, b) = as_i64(a, b);
                let result = (a as u32).pow(b as u32);
                Ok(NaslValue::Number(result as i64))
            }),
            TokenCategory::Tilde => self.execute(stmts, |a, _| Ok((!i64::from(&a)).into())),
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
                // neither empty statements nor statements over 2 arguments should ever happen
                // because it is handled as a SyntaxError. Therefore we don't double check and
                // and let it run into a index out of bound panic to immediately escalate.
                let repeat = {
                    let last = self.resolve(&stmts[1])?;
                    i64::from(&last)
                };
                if repeat == 0 {
                    // don't execute;
                    return Ok(NaslValue::Null);
                }
                let repeatable = &stmts[0];
                for _ in 1..repeat - 1 {
                    self.resolve(repeatable)?;
                }
                self.resolve(repeatable)
            }

            o => Err(InterpretError::wrong_category(o)),
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::*;

    macro_rules! create_test {
        ($($name:tt: $code:expr => $result:expr),*) => {

        $(
            #[test]
            fn $name() {
                let register = Register::default();
                let binding = ContextBuilder::default();
                let context = binding.build();
                let mut interpreter = Interpreter::new(register, &context);
                let parser = parse($code).map(|x|
                    interpreter.resolve(&x.expect("unexpected parse error"))
                );
                assert_eq!(parser.last(), Some(Ok($result)));
            }
        )*
        };
    }
    create_test! {
        numeric_plus: "1+2;" => 3.into(),
        cast_to_string_middle_plus: "1+\"\"+2;" => "12".into(),
        cast_to_string_end_plus: "1+2+\"\";" => "3".into(),
        cast_to_string_end_plus_4: "1+2+\"\" + 4;" => "34".into(),
        cast_to_string_minus: "11-\"1\";" => "1".into(),
        string_plus: "\"hello \" + \"world!\";" => "hello world!".into(),
        string_minus : "\"hello \" - 'o ';" => "hell".into(),
        data_plus: "'hello ' + 'world!';" => "hello world!".as_bytes().into(),
        data_minus: "'hello ' - 'o ';" => "hell".as_bytes().into(),

        cast_to_data_middle_plus: "1+''+2;" => "12".as_bytes().into(),
        cast_to_data_end_plus: "1+2+'';" => "3".as_bytes().into(),
        cast_to_data_end_plus_4: "1+2+'' + 4;" => "34".as_bytes().into(),
        cast_to_data_minus: "11-'1';" => "1".as_bytes().into(),
        numeric_minus : "1 - 2;" => NaslValue::Number(-1),
        multiplication: "1*2;" => 2.into(),
        division: "512/2;" => 256.into(),
        modulo: "512%2;" => 0.into(),
        left_shift: "512 << 2;" => 2048.into(),
        right_shift: "512 >> 2;" => 128.into(),
        unsigned_right_shift: "-2 >>> 2;" => 1073741823.into(),
        and: "-2 & 2;" => 2.into(),
        or: "-2 | 2;" => NaslValue::Number(-2),
        xor: "-2 ^ 2;" => NaslValue::Number(-4),
        pow: "2 ** 2;" => 4.into(),
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
        x_gonna_give_it_ya: "function test() { }; test('hi') x 200;" => NaslValue::Null
    }
}
