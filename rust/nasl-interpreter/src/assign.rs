use std::ops::Range;

use nasl_syntax::{AssignOrder, Statement, Token, TokenCategory};

use crate::{
    error::InterpretError, interpreter::InterpretResult, ContextType, Interpreter, NaslValue,
};
use Statement::*;

/// Is a trait to handle function assignments within nasl.
pub(crate) trait AssignExtension {
    /// Assigns a right value to a left value and returns either previous or new value based on the order
    fn assign(
        &mut self,
        category: TokenCategory,
        order: AssignOrder,
        left: Statement,
        right: Statement,
    ) -> InterpretResult;
}

#[inline(always)]
fn prepare_array(idx: &NaslValue, left: NaslValue) -> (usize, Vec<NaslValue>) {
    let idx = i32::from(idx) as usize;
    let mut arr: Vec<NaslValue> = match left {
        NaslValue::Array(x) => x,
        _ => {
            vec![left.clone()]
        }
    };

    for _ in arr.len()..idx + 1 {
        arr.push(NaslValue::Null)
    }
    (idx, arr)
}
impl<'a> Interpreter<'a> {
    #[inline(always)]
    fn named_value(&self, key: &str) -> Result<NaslValue, InterpretError> {
        match self
            .registrat()
            .named(key)
            .unwrap_or(&ContextType::Value(NaslValue::Null))
        {
            ContextType::Function(_) => Err(InterpretError {
                reason: format!("{} is not assignable", key),
            }),
            ContextType::Value(val) => Ok(val.clone()),
        }
    }

    #[inline(always)]
    fn store_return(
        &mut self,
        key: &str,
        lookup: Option<NaslValue>,
        right: &NaslValue,
        result: impl Fn(&NaslValue, &NaslValue) -> NaslValue,
    ) -> InterpretResult {
        let left = self.named_value(key)?;
        let result = match lookup {
            None => {
                let result = result(&left, right);
                let register = self.registrat.last_mut();
                register.add_named(key, ContextType::Value(result.clone()));
                result
            }
            Some(idx) => {
                let (idx, mut arr) = prepare_array(&idx, left);
                let result = result(&arr[idx], right);
                arr[idx] = result.clone();
                let register = self.registrat.last_mut();
                register.add_named(key, ContextType::Value(NaslValue::Array(arr)));
                result
            }
        };
        Ok(result)
    }

    #[inline(always)]
    fn dynamic_return(
        &mut self,
        order: &AssignOrder,
        key: &str,
        lookup: Option<NaslValue>,
        result: impl Fn(&NaslValue, &NaslValue) -> NaslValue,
    ) -> InterpretResult {
        match order {
            AssignOrder::AssignReturn => self.store_return(key, lookup, &NaslValue::Null, result),
            AssignOrder::ReturnAssign => {
                let left = self.named_value(key)?;
                let result = match lookup {
                    None => {
                        let result = result(&left, &NaslValue::Null);
                        let register = self.registrat.last_mut();
                        register.add_named(key, ContextType::Value(result));
                        left
                    }
                    Some(idx) => {
                        let (idx, mut arr) = prepare_array(&idx, left);
                        let orig = arr[idx].clone();
                        let result = result(&orig, &NaslValue::Null);
                        arr[idx] = result;
                        let register = self.registrat.last_mut();
                        register.add_named(key, ContextType::Value(NaslValue::Array(arr)));
                        orig
                    }
                };
                Ok(result)
            }
        }
    }
}

impl<'a> AssignExtension for Interpreter<'a> {
    fn assign(
        &mut self,
        category: TokenCategory,
        order: AssignOrder,
        left: Statement,
        right: Statement,
    ) -> InterpretResult {
        let (key, lookup) = {
            match left {
                Variable(token) | Array(token, None) => (&self.code[Range::from(token)], None),
                Array(token, Some(stmt)) => {
                    (&self.code[Range::from(token)], Some(self.resolve(*stmt)?))
                }
                _ => {
                    return Err(InterpretError {
                        reason: format!("{:?} is not supported", left),
                    })
                }
            }
        };
        let val = self.resolve(right)?;
        match category {
            TokenCategory::Equal => match lookup {
                Some(idx) => {
                    let idx = i32::from(&idx) as usize;
                    let mut arr: Vec<NaslValue> = match self.registrat().named(key) {
                        Some(ContextType::Value(NaslValue::Array(x))) => x.clone(),
                        Some(ContextType::Value(x)) => {
                            vec![x.clone()]
                        }
                        _ => {
                            vec![]
                        }
                    };

                    for _ in arr.len()..idx + 1 {
                        arr.push(NaslValue::Null)
                    }
                    arr[idx] = val.clone();
                    let register = self.registrat.last_mut();
                    register.add_named(key, ContextType::Value(NaslValue::Array(arr.clone())));
                    Ok(val)
                }
                None => {
                    let register = self.registrat.last_mut();
                    register.add_named(key, ContextType::Value(val.clone()));
                    Ok(val)
                }
            },
            TokenCategory::PlusEqual => self.store_return(key, lookup, &val, |left, right| {
                NaslValue::Number(i32::from(left) + i32::from(right))
            }),
            TokenCategory::MinusEqual => self.store_return(key, lookup, &val, |left, right| {
                NaslValue::Number(i32::from(left) - i32::from(right))
            }),
            TokenCategory::SlashEqual => self.store_return(key, lookup, &val, |left, right| {
                NaslValue::Number(i32::from(left) / i32::from(right))
            }),
            TokenCategory::StarEqual => self.store_return(key, lookup, &val, |left, right| {
                NaslValue::Number(i32::from(left) * i32::from(right))
            }),
            TokenCategory::GreaterGreaterEqual => {
                self.store_return(key, lookup, &val, |left, right| {
                    NaslValue::Number(i32::from(left) >> i32::from(right))
                })
            }
            TokenCategory::LessLessEqual => self.store_return(key, lookup, &val, |left, right| {
                NaslValue::Number(i32::from(left) << i32::from(right))
            }),
            TokenCategory::GreaterGreaterGreaterEqual => {
                self.store_return(key, lookup, &val, |left, right| {
                    // get rid of minus sign
                    let left = i32::from(left) as u32;
                    let right = i32::from(right) as u32;
                    NaslValue::Number((left << right) as i32)
                })
            }
            TokenCategory::PercentEqual => self.store_return(key, lookup, &val, |left, right| {
                NaslValue::Number(i32::from(left) % i32::from(right))
            }),
            TokenCategory::PlusPlus => self.dynamic_return(&order, key, lookup, |left, _| {
                NaslValue::Number(i32::from(left) + 1)
            }),
            TokenCategory::MinusMinus => self.dynamic_return(&order, key, lookup, |left, _| {
                NaslValue::Number(i32::from(left) - 1)
            }),
            _ => Err(InterpretError {
                reason: format!("{:?} is not supported", category),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use nasl_syntax::parse;
    use sink::DefaultSink;

    use crate::{error::InterpretError, Interpreter, NaslValue};

    #[test]
    fn variables() {
        let code = r###"
        a = 12;
        a += 13;
        a -= 2;
        a /= 2;
        a *= 2;
        a >>= 2;
        a <<= 2;
        a >>>= 2;
        a %= 2;
        a++;
        ++a;
        a--;
        --a;
        "###;
        let storage = DefaultSink::new(false);
        let mut interpreter = Interpreter::new(&storage, vec![], Some("1"), None, code);
        let mut parser = parse(code).map(|x| match x {
            Ok(x) => interpreter.resolve(x),
            Err(x) => Err(InterpretError {
                reason: x.to_string(),
            }),
        });
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(12))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(25))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(23))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(11))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(22))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(5))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(20))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(80))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(0))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(0))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(2))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(2))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(0))));
    }
    #[test]
    fn arrays() {
        let code = r###"
        a[0] = 12;
        a[0] += 13;
        a[0] -= 2;
        a[0] /= 2;
        a[0] *= 2;
        a[0] >>= 2;
        a[0] <<= 2;
        a[0] >>>= 2;
        a[0] %= 2;
        a[0]++;
        ++a[0];
        "###;
        let storage = DefaultSink::new(false);
        let mut interpreter = Interpreter::new(&storage, vec![], Some("1"), None, code);
        let mut parser = parse(code).map(|x| match x {
            Ok(x) => interpreter.resolve(x),
            Err(x) => Err(InterpretError {
                reason: x.to_string(),
            }),
        });
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(12))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(25))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(23))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(11))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(22))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(5))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(20))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(80))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(0))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(0))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(2))));
    }
}
