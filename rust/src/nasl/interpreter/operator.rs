// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::nasl::syntax::{Statement, TokenCategory};
use regex::Regex;

use crate::nasl::interpreter::{error::InterpretError, interpreter::InterpretResult, Interpreter};

use crate::nasl::syntax::NaslValue;

impl Interpreter<'_> {
    async fn execute(
        &mut self,
        stmts: &[Statement],
        result: impl Fn(NaslValue, Option<NaslValue>) -> InterpretResult,
    ) -> InterpretResult {
        // neither empty statements nor statements over 2 arguments should ever happen
        // because it is handled as a SyntaxError. Therefore we don't double check and
        // and let it run into a index out of bound panic to immediately escalate.
        let (left, right) = {
            let first = self.resolve(&stmts[0]).await?;
            if stmts.len() == 1 {
                (first, None)
            } else {
                (first, Some(self.resolve(&stmts[1]).await?))
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

impl Interpreter<'_> {
    /// Return the result of a NASL operator.
    pub async fn operator(
        &mut self,
        category: &TokenCategory,
        stmts: &[Statement],
    ) -> InterpretResult {
        match category {
            // number and string
            TokenCategory::Plus => {
                self.execute(stmts, |a, b| match a {
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
                })
                .await
            }
            TokenCategory::Minus => {
                self.execute(stmts, |a, b| match a {
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
                })
                .await
            }
            // number
            TokenCategory::Star => self.execute(stmts, |a, b| num_expr!(* a b)).await,
            TokenCategory::Slash => self.execute(stmts, |a, b| num_expr!(/ a b)).await,
            TokenCategory::Percent => self.execute(stmts, |a, b| num_expr!(% a b)).await,
            TokenCategory::LessLess => self.execute(stmts, |a, b| num_expr!(<< a b)).await,
            TokenCategory::GreaterGreater => self.execute(stmts, |a, b| num_expr!(>> a b)).await,
            // let left_casted = left as u32; (left_casted >> right) as i64
            TokenCategory::GreaterGreaterGreater => {
                self.execute(
                    stmts,
                    //|a, b| num_expr!(|a, b| ((a as u32) >> b) as i32 => a b),
                    |a, b| {
                        let (left, right) = as_i64(a, b);
                        let result = ((left as u32) >> right) as i32;
                        Ok(NaslValue::Number(result as i64))
                    },
                )
                .await
            }
            TokenCategory::Ampersand => self.execute(stmts, |a, b| num_expr!(& a b)).await,
            TokenCategory::Pipe => self.execute(stmts, |a, b| num_expr!(| a b)).await,
            TokenCategory::Caret => self.execute(stmts, |a, b| num_expr!(^ a b)).await,
            TokenCategory::StarStar => {
                self.execute(stmts, |a, b| {
                    let (a, b) = as_i64(a, b);
                    let result = (a as u32).pow(b as u32);
                    Ok(NaslValue::Number(result as i64))
                })
                .await
            }
            TokenCategory::Tilde => {
                self.execute(stmts, |a, _| Ok((!i64::from(&a)).into()))
                    .await
            }
            // string
            TokenCategory::EqualTilde => self.execute(stmts, match_regex).await,
            TokenCategory::BangTilde => self.execute(stmts, not_match_regex).await,
            TokenCategory::GreaterLess => {
                self.execute(stmts, |a, b| {
                    let substr = b.map(|x| x.to_string()).unwrap_or_default();
                    Ok(NaslValue::Boolean(a.to_string().contains(&substr)))
                })
                .await
            }
            TokenCategory::GreaterBangLess => {
                self.execute(stmts, |a, b| {
                    let substr = b.map(|x| x.to_string()).unwrap_or_default();
                    Ok(NaslValue::Boolean(!a.to_string().contains(&substr)))
                })
                .await
            }
            // bool
            TokenCategory::Bang => {
                self.execute(stmts, |a, _| Ok(NaslValue::Boolean(!bool::from(a))))
                    .await
            }
            TokenCategory::AmpersandAmpersand => {
                self.execute(stmts, |a, b| {
                    let right = b.map(bool::from).unwrap_or_default();
                    Ok(NaslValue::Boolean(bool::from(a) && right))
                })
                .await
            }
            TokenCategory::PipePipe => {
                self.execute(stmts, |a, b| {
                    let right = b.map(bool::from).unwrap_or_default();
                    Ok(NaslValue::Boolean(bool::from(a) || right))
                })
                .await
            }
            TokenCategory::EqualEqual => {
                self.execute(stmts, |a, b| {
                    let right = b.unwrap_or(NaslValue::Null);
                    Ok(NaslValue::Boolean(a == right))
                })
                .await
            }
            TokenCategory::BangEqual => {
                self.execute(stmts, |a, b| {
                    let right = b.unwrap_or(NaslValue::Null);
                    Ok(NaslValue::Boolean(a != right))
                })
                .await
            }
            TokenCategory::Greater => {
                self.execute(stmts, |a, b| {
                    let right = b.map(|x| i64::from(&x)).unwrap_or_default();
                    Ok(NaslValue::Boolean(i64::from(&a) > right))
                })
                .await
            }
            TokenCategory::Less => {
                self.execute(stmts, |a, b| {
                    let right = b.map(|x| i64::from(&x)).unwrap_or_default();
                    Ok(NaslValue::Boolean(i64::from(&a) < right))
                })
                .await
            }
            TokenCategory::GreaterEqual => {
                self.execute(stmts, |a, b| {
                    let right = b.map(|x| i64::from(&x)).unwrap_or_default();
                    Ok(NaslValue::Boolean(i64::from(&a) >= right))
                })
                .await
            }
            TokenCategory::LessEqual => {
                self.execute(stmts, |a, b| {
                    let right = b.map(|x| i64::from(&x)).unwrap_or_default();
                    Ok(NaslValue::Boolean(i64::from(&a) <= right))
                })
                .await
            }
            TokenCategory::X => {
                // neither empty statements nor statements over 2 arguments should ever happen
                // because it is handled as a SyntaxError. Therefore we don't double check and
                // and let it run into a index out of bound panic to immediately escalate.
                let repeat = {
                    let last = self.resolve(&stmts[1]).await?;
                    i64::from(&last)
                };
                if repeat == 0 {
                    // don't execute;
                    return Ok(NaslValue::Null);
                }
                let repeatable = &stmts[0];
                for _ in 1..repeat - 1 {
                    self.resolve(repeatable).await?;
                }
                self.resolve(repeatable).await
            }

            o => Err(InterpretError::wrong_category(o)),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::nasl::test_prelude::*;
    macro_rules! create_test {
        ($($name:tt: $code:expr => $result:expr),*) => {

            $(
                #[test]
                fn $name() {
                    let mut t = TestBuilder::default();
                    t.ok($code, $result);
                }
            )*
        };
    }

    create_test! {
        numeric_plus: "1+2;" => 3,
        cast_to_string_middle_plus: "1+\"\"+2;" => "12",
        cast_to_string_end_plus: "1+2+\"\";" => "3",
        cast_to_string_end_plus_4: "1+2+\"\" + 4;" => "34",
        cast_to_string_minus: "11-\"1\";" => "1",
        string_plus: "\"hello \" + \"world!\";" => "hello world!",
        string_minus : "\"hello \" - 'o ';" => "hell",
        data_plus: "'hello ' + 'world!';" => "hello world!".as_bytes(),
        data_minus: "'hello ' - 'o ';" => "hell".as_bytes(),

        cast_to_data_middle_plus: "1+''+2;" => "12".as_bytes(),
        cast_to_data_end_plus: "1+2+'';" => "3".as_bytes(),
        cast_to_data_end_plus_4: "1+2+'' + 4;" => "34".as_bytes(),
        cast_to_data_minus: "11-'1';" => "1".as_bytes(),
        numeric_minus : "1 - 2;" => -1,
        multiplication: "1*2;" => 2,
        division: "512/2;" => 256,
        modulo: "512%2;" => 0,
        left_shift: "512 << 2;" => 2048,
        right_shift: "512 >> 2;" => 128,
        unsigned_right_shift: "-2 >>> 2;" => 1073741823,
        and: "-2 & 2;" => 2,
        or: "-2 | 2;" => -2,
        xor: "-2 ^ 2;" => -4,
        pow: "2 ** 2;" => 4,
        not: "~2;" => -3,
        r_match: "'hello' =~ 'hell';" => true,
        r_not_match: "'hello' !~ 'hell';" => false,
        contains: "'hello' >< 'hell';" => true,
        not_contains: "'hello' >!< 'hell';" => false,
        bool_not: "!23;" => false,
        bool_not_reverse: "!0;" => true,
        bool_and: "1 && 1;" => true,
        bool_or: "1 || 0;" => true,
        equals_string: "'1' == '1';" => true,
        equals_number: "1 == 1;" => true,
        unequal: "1 != 1;" => false,
        greater: "1 > 0;" => true,
        less: "1 < 2;" => true,
        greater_equal: "1 >= 1;" => true,
        less_equal: "1 <= 1;" => true
    }

    #[test]
    fn x_gonna_give_it_ya() {
        let mut t = TestBuilder::default();
        t.run_all("function test() { }; test('hi') x 200;");
        assert_eq!(t.results().pop().unwrap().unwrap(), NaslValue::Null);
    }
}
