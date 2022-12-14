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

impl<'a> Interpreter<'a> {
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

    fn store_return(
        &mut self,
        key: &str,
        right: NaslValue,
        result: impl Fn(NaslValue, NaslValue) -> NaslValue,
    ) -> InterpretResult {
        let left = self.named_value(key)?;
        let result = result(left, right);
        let register = self.registrat.last_mut();
        register.add_named(key, ContextType::Value(result.clone()));
        Ok(result)
    }

    fn return_store(
        &mut self,
        key: &str,
        right: NaslValue,
        result: impl Fn(NaslValue, NaslValue) -> NaslValue,
    ) -> InterpretResult {
        let left = self.named_value(key)?;
        let result = result(left.clone(), right);
        let register = self.registrat.last_mut();
        register.add_named(key, ContextType::Value(result));
        println!("in return_store {:?}", left);
        Ok(left)
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
        let val = self.resolve(right)?;
        match left {
            Variable(token) => {
                let key: &str = &self.code[Range::from(token)];
                match category {
                    TokenCategory::Equal => {
                        let register = self.registrat.last_mut();
                        register.add_named(key, ContextType::Value(val.clone()));
                        Ok(val)
                    }
                    TokenCategory::PlusEqual => self.store_return(key, val, |left, right| {
                        NaslValue::Number(i32::from(left) + i32::from(right))
                    }),
                    TokenCategory::MinusEqual => self.store_return(key, val, |left, right| {
                        NaslValue::Number(i32::from(left) - i32::from(right))
                    }),
                    TokenCategory::SlashEqual => self.store_return(key, val, |left, right| {
                        NaslValue::Number(i32::from(left) / i32::from(right))
                    }),
                    TokenCategory::StarEqual => self.store_return(key, val, |left, right| {
                        NaslValue::Number(i32::from(left) * i32::from(right))
                    }),
                    TokenCategory::GreaterGreaterEqual => {
                        self.store_return(key, val, |left, right| {
                            NaslValue::Number(i32::from(left) >> i32::from(right))
                        })
                    }
                    TokenCategory::LessLessEqual => self.store_return(key, val, |left, right| {
                        NaslValue::Number(i32::from(left) << i32::from(right))
                    }),
                    TokenCategory::GreaterGreaterGreaterEqual => {
                        self.store_return(key, val, |left, right| {
                            // get rid of minus sign
                            let left = i32::from(left) as u32;
                            let right = i32::from(right) as u32;
                            NaslValue::Number((left << right) as i32)
                        })
                    }
                    TokenCategory::PercentEqual => self.store_return(key, val, |left, right| {
                        NaslValue::Number(i32::from(left) % i32::from(right))
                    }),
                    TokenCategory::PlusPlus => {
                        let assign = |left, _| NaslValue::Number(i32::from(left) + 1);
                        match order {
                            AssignOrder::AssignReturn => {
                                self.store_return(key, NaslValue::Null, assign)
                            }
                            AssignOrder::ReturnAssign => {
                                self.return_store(key, NaslValue::Null, assign)
                            }
                        }
                    }
                    _ => Err(InterpretError {
                        reason: format!("{:?} is not supported", category),
                    }),
                }
            }
            Array(_, _) => todo!("arrays are not yet implemented"),
            _ => Err(InterpretError {
                reason: format!("{:?} is not supported", left),
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
