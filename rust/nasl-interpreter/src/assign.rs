use std::collections::HashMap;

use nasl_syntax::{AssignOrder, Statement, TokenCategory};

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
    let idx = i64::from(idx) as usize;
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

#[inline(always)]
fn prepare_dict(left: NaslValue) -> HashMap<String, NaslValue> {
    match left {
        NaslValue::Array(x) => x
            .into_iter()
            .enumerate()
            .map(|(i, v)| (i.to_string(), v))
            .collect(),
        NaslValue::Dict(x) => x,
        NaslValue::Null => HashMap::new(),
        x => HashMap::from([("0".to_string(), x)]),
    }
}

impl<'a> Interpreter<'a> {
    #[inline(always)]
    fn named_value(&self, key: &str) -> Result<NaslValue, InterpretError> {
        match self
            .registrat()
            .named(key)
            .unwrap_or(&ContextType::Value(NaslValue::Null))
        {
            ContextType::Function(_, _) => Err(InterpretError {
                reason: format!("{} is not assignable", key),
            }),
            ContextType::Value(val) => Ok(val.clone()),
        }
    }

    fn handle_dict(
        &mut self,
        key: &str,
        idx: String,
        left: NaslValue,
        right: &NaslValue,
        return_original: &AssignOrder,
        result: impl Fn(&NaslValue, &NaslValue) -> NaslValue,
    ) -> NaslValue {
        let mut dict = prepare_dict(left);
        match return_original {
            AssignOrder::ReturnAssign => {
                let original = dict.get(&idx).unwrap_or(&NaslValue::Null).clone();
                let result = result(&original, right);
                dict.insert(idx, result);
                let register = self.registrat.last_mut();
                register.add_named(key, ContextType::Value(NaslValue::Dict(dict)));
                original
            }
            AssignOrder::AssignReturn => {
                let original = dict.get(&idx).unwrap_or(&NaslValue::Null);
                let result = result(original, right);
                dict.insert(idx, result.clone());
                let register = self.registrat.last_mut();
                register.add_named(key, ContextType::Value(NaslValue::Dict(dict)));
                result
            }
        }
    }

    fn handle_array(
        &mut self,
        key: &str,
        idx: &NaslValue,
        left: NaslValue,
        right: &NaslValue,
        return_original: &AssignOrder,
        result: impl Fn(&NaslValue, &NaslValue) -> NaslValue,
    ) -> NaslValue {
        let (idx, mut arr) = prepare_array(idx, left);
        match return_original {
            AssignOrder::ReturnAssign => {
                let orig = arr[idx].clone();
                let result = result(&orig, right);
                arr[idx] = result;
                let register = self.registrat.last_mut();
                register.add_named(key, ContextType::Value(NaslValue::Array(arr)));
                orig
            }
            AssignOrder::AssignReturn => {
                let result = result(&arr[idx], right);
                arr[idx] = result.clone();
                let register = self.registrat.last_mut();
                register.add_named(key, ContextType::Value(NaslValue::Array(arr)));
                result
            }
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
        self.dynamic_return(key, &AssignOrder::AssignReturn, lookup, right, result)
    }

    #[inline(always)]
    fn dynamic_return(
        &mut self,
        key: &str,
        order: &AssignOrder,
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
                match order {
                    AssignOrder::AssignReturn => result,
                    AssignOrder::ReturnAssign => left,
                }
            }
            Some(idx) => match idx {
                NaslValue::String(idx) => self.handle_dict(key, idx, left, right, order, result),
                _ => match left {
                    NaslValue::Dict(_) => {
                        self.handle_dict(key, idx.to_string(), left, right, order, result)
                    }
                    _ => self.handle_array(key, &idx, left, right, order, result),
                },
            },
        };
        Ok(result)
    }
    #[inline(always)]
    fn without_right(
        &mut self,
        order: &AssignOrder,
        key: &str,
        lookup: Option<NaslValue>,
        result: impl Fn(&NaslValue, &NaslValue) -> NaslValue,
    ) -> InterpretResult {
        self.dynamic_return(key, order, lookup, &NaslValue::Null, result)
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
                Variable(token) => (Self::identifier(&token)?, None),
                Array(token, Some(stmt)) => {
                    (Self::identifier(&token)?, Some(self.resolve(*stmt)?))
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
            TokenCategory::Equal => self.store_return(&key, lookup, &val, |_, right| right.clone()),
            TokenCategory::PlusEqual => self.store_return(&key, lookup, &val, |left, right| {
                NaslValue::Number(i64::from(left) + i64::from(right))
            }),
            TokenCategory::MinusEqual => self.store_return(&key, lookup, &val, |left, right| {
                NaslValue::Number(i64::from(left) - i64::from(right))
            }),
            TokenCategory::SlashEqual => self.store_return(&key, lookup, &val, |left, right| {
                NaslValue::Number(i64::from(left) / i64::from(right))
            }),
            TokenCategory::StarEqual => self.store_return(&key, lookup, &val, |left, right| {
                NaslValue::Number(i64::from(left) * i64::from(right))
            }),
            TokenCategory::GreaterGreaterEqual => {
                self.store_return(&key, lookup, &val, |left, right| {
                    NaslValue::Number(i64::from(left) >> i64::from(right))
                })
            }
            TokenCategory::LessLessEqual => self.store_return(&key, lookup, &val, |left, right| {
                NaslValue::Number(i64::from(left) << i64::from(right))
            }),
            TokenCategory::GreaterGreaterGreaterEqual => {
                self.store_return(&key, lookup, &val, |left, right| {
                    // get rid of minus sign
                    let left = i64::from(left) as u32;
                    let right = i64::from(right) as u32;
                    NaslValue::Number((left << right) as i64)
                })
            }
            TokenCategory::PercentEqual => self.store_return(&key, lookup, &val, |left, right| {
                NaslValue::Number(i64::from(left) % i64::from(right))
            }),
            TokenCategory::PlusPlus => self.without_right(&order, &key, lookup, |left, _| {
                NaslValue::Number(i64::from(left) + 1)
            }),
            TokenCategory::MinusMinus => self.without_right(&order, &key, lookup, |left, _| {
                NaslValue::Number(i64::from(left) - 1)
            }),
            _ => Err(InterpretError {
                reason: format!("{:?} is not supported", category),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use nasl_syntax::parse;
    use sink::DefaultSink;

    use crate::{error::InterpretError, Interpreter, NaslValue, context::Register, loader::NoOpLoader};

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
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
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
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
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
    #[test]
    fn implicit_extend() {
        let code = r###"
        a[2] = 12;
        a;
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser = parse(code).map(|x| match x {
            Ok(x) => interpreter.resolve(x),
            Err(x) => Err(InterpretError {
                reason: x.to_string(),
            }),
        });
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(12))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Array(vec![NaslValue::Null, NaslValue::Null, NaslValue::Number(12)]))));
    }

    #[test]
    fn implicit_transformation() {
        let code = r###"
        a = 12;
        a;
        a[2] = 12;
        a;
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser = parse(code).map(|x| match x {
            Ok(x) => interpreter.resolve(x),
            Err(x) => Err(InterpretError {
                reason: x.to_string(),
            }),
        });
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(12))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(12))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(12))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Array(vec![NaslValue::Number(12), NaslValue::Null, NaslValue::Number(12)]))));
    }

    #[test]
    fn dict() {
        let code = r###"
        a['hi'] = 12;
        a;
        a['hi'];
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser = parse(code).map(|x| match x {
            Ok(x) => interpreter.resolve(x),
            Err(x) => Err(InterpretError {
                reason: x.to_string(),
            }),
        });
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(12))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Dict(HashMap::from([("hi".to_owned(), NaslValue::Number(12))])))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Number(12))));
    }
    #[test]
    fn empty_bracklet() {
        let code = r###"
        a[] = 12;
        "###;
        let storage = DefaultSink::new(false);
        let mut register = Register::default();
        let loader = NoOpLoader::default();
        let mut interpreter = Interpreter::new("1", &storage, &loader, &mut register);
        let mut parser = parse(code).map(|x| match x {
            Ok(x) => interpreter.resolve(x),
            Err(x) => Err(InterpretError {
                reason: x.to_string(),
            }),
        });
        assert!(matches!(parser.next(), Some(Err(_))));
    }
}
