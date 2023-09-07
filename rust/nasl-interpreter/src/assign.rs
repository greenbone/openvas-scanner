// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::HashMap;

use nasl_syntax::{AssignOrder, Statement, TokenCategory};

use crate::{error::InterpretError, interpreter::InterpretResult, Interpreter};
use nasl_builtin_utils::ContextType;
use nasl_syntax::NaslValue;
use Statement::*;

/// Is a trait to handle function assignments within nasl.
pub(crate) trait AssignExtension {
    /// Assigns a right value to a left value and returns either previous or new value based on the order
    fn assign(
        &mut self,
        category: &TokenCategory,
        order: &AssignOrder,
        left: &Statement,
        right: &Statement,
    ) -> InterpretResult;
}

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

impl<'a, K> Interpreter<'a, K>
where
    K: AsRef<str>,
{
    fn save(&mut self, idx: usize, key: &str, value: NaslValue) {
        self.registrat
            .add_to_index(idx, key, ContextType::Value(value));
    }

    fn named_value(&self, key: &str) -> Result<(usize, NaslValue), InterpretError> {
        match self
            .registrat()
            .index_named(key)
            .unwrap_or((0, &ContextType::Value(NaslValue::Null)))
        {
            (_, ContextType::Function(_, _)) => Err(InterpretError::expected_value()),
            (idx, ContextType::Value(val)) => Ok((idx, val.clone())),
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn handle_dict(
        &mut self,
        ridx: usize,
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
                self.save(ridx, key, NaslValue::Dict(dict));
                original
            }
            AssignOrder::AssignReturn => {
                let original = dict.get(&idx).unwrap_or(&NaslValue::Null);
                let result = result(original, right);
                dict.insert(idx, result.clone());
                self.save(ridx, key, NaslValue::Dict(dict));
                result
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_array(
        &mut self,
        ridx: usize,
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
                self.save(ridx, key, NaslValue::Array(arr));
                orig
            }
            AssignOrder::AssignReturn => {
                let result = result(&arr[idx], right);
                arr[idx] = result.clone();
                self.save(ridx, key, NaslValue::Array(arr));
                result
            }
        }
    }

    fn store_return(
        &mut self,
        key: &str,
        lookup: Option<NaslValue>,
        right: &NaslValue,
        result: impl Fn(&NaslValue, &NaslValue) -> NaslValue,
    ) -> InterpretResult {
        self.dynamic_return(key, &AssignOrder::AssignReturn, lookup, right, result)
    }

    fn dynamic_return(
        &mut self,
        key: &str,
        order: &AssignOrder,
        lookup: Option<NaslValue>,
        right: &NaslValue,
        result: impl Fn(&NaslValue, &NaslValue) -> NaslValue,
    ) -> InterpretResult {
        let (ridx, left) = self.named_value(key)?;
        let result = match lookup {
            None => {
                let result = result(&left, right);
                self.save(ridx, key, result.clone());
                match order {
                    AssignOrder::AssignReturn => result,
                    AssignOrder::ReturnAssign => left,
                }
            }
            Some(idx) => match idx {
                NaslValue::String(idx) => {
                    self.handle_dict(ridx, key, idx, left, right, order, result)
                }
                NaslValue::Data(idx) => {
                    let idx = idx.into_iter().map(|x| x as char).collect();
                    self.handle_dict(ridx, key, idx, left, right, order, result)
                }
                _ => match left {
                    NaslValue::Dict(_) => {
                        self.handle_dict(ridx, key, idx.to_string(), left, right, order, result)
                    }
                    _ => self.handle_array(ridx, key, &idx, left, right, order, result),
                },
            },
        };
        Ok(result)
    }
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

impl<'a, K> AssignExtension for Interpreter<'a, K>
where
    K: AsRef<str>,
{
    fn assign(
        &mut self,
        category: &TokenCategory,
        order: &AssignOrder,
        left: &Statement,
        right: &Statement,
    ) -> InterpretResult {
        let (key, lookup) = {
            match left {
                Variable(ref token) => (Self::identifier(token)?, None),
                Array(ref token, Some(stmt), _) => {
                    (Self::identifier(token)?, Some(self.resolve(stmt)?))
                }
                Array(ref token, None, _) => (Self::identifier(token)?, None),
                _ => return Err(InterpretError::unsupported(left, "Array or Variable")),
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
            TokenCategory::PlusPlus => self.without_right(order, &key, lookup, |left, _| {
                NaslValue::Number(i64::from(left) + 1)
            }),
            TokenCategory::MinusMinus => self.without_right(order, &key, lookup, |left, _| {
                NaslValue::Number(i64::from(left) - 1)
            }),

            cat => Err(InterpretError::wrong_category(cat)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::*;
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
        let mut register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(parser.next(), Some(Ok(12.into())));
        assert_eq!(parser.next(), Some(Ok(25.into())));
        assert_eq!(parser.next(), Some(Ok(23.into())));
        assert_eq!(parser.next(), Some(Ok(11.into())));
        assert_eq!(parser.next(), Some(Ok(22.into())));
        assert_eq!(parser.next(), Some(Ok(5.into())));
        assert_eq!(parser.next(), Some(Ok(20.into())));
        assert_eq!(parser.next(), Some(Ok(80.into())));
        assert_eq!(parser.next(), Some(Ok(0.into())));
        assert_eq!(parser.next(), Some(Ok(0.into())));
        assert_eq!(parser.next(), Some(Ok(2.into())));
        assert_eq!(parser.next(), Some(Ok(2.into())));
        assert_eq!(parser.next(), Some(Ok(0.into())));
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
        let mut register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(parser.next(), Some(Ok(12.into())));
        assert_eq!(parser.next(), Some(Ok(25.into())));
        assert_eq!(parser.next(), Some(Ok(23.into())));
        assert_eq!(parser.next(), Some(Ok(11.into())));
        assert_eq!(parser.next(), Some(Ok(22.into())));
        assert_eq!(parser.next(), Some(Ok(5.into())));
        assert_eq!(parser.next(), Some(Ok(20.into())));
        assert_eq!(parser.next(), Some(Ok(80.into())));
        assert_eq!(parser.next(), Some(Ok(0.into())));
        assert_eq!(parser.next(), Some(Ok(0.into())));
        assert_eq!(parser.next(), Some(Ok(2.into())));
    }
    #[test]
    fn implicit_extend() {
        let code = r###"
        a[2] = 12;
        a;
        "###;
        let mut register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(parser.next(), Some(Ok(12.into())));
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Array(vec![
                NaslValue::Null,
                NaslValue::Null,
                12.into()
            ])))
        );
    }

    #[test]
    fn implicit_transformation() {
        let code = r###"
        a = 12;
        a;
        a[2] = 12;
        a;
        "###;
        let mut register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(parser.next(), Some(Ok(12.into())));
        assert_eq!(parser.next(), Some(Ok(12.into())));
        assert_eq!(parser.next(), Some(Ok(12.into())));
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Array(vec![
                12.into(),
                NaslValue::Null,
                12.into()
            ])))
        );
    }

    #[test]
    fn dict() {
        let code = r###"
        a['hi'] = 12;
        a;
        a['hi'];
        "###;
        let mut register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(parser.next(), Some(Ok(12.into())));
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Dict(HashMap::from([(
                "hi".to_owned(),
                12.into()
            )]))))
        );
        assert_eq!(parser.next(), Some(Ok(12.into())));
    }

    #[test]
    fn array_creation() {
        let code = r###"
        a = [1, 2, 3];
        "###;
        let mut register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Array(vec![1.into(), 2.into(), 3.into()])))
        );
    }
}
