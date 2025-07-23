// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::HashMap;

use super::register::Var;
use crate::nasl::error::Spanned;
use crate::nasl::interpreter::ExprLocation;
use crate::nasl::interpreter::error::ExprError;
use crate::nasl::interpreter::nasl_value::RuntimeValue;
use crate::nasl::syntax::grammar::Assignment;
use crate::nasl::syntax::grammar::AssignmentOperatorKind;
use crate::nasl::syntax::grammar::Increment;
use crate::nasl::syntax::grammar::IncrementKind;
use crate::nasl::syntax::grammar::IncrementOperatorKind;
use crate::nasl::syntax::grammar::PlaceExpr;

use super::Interpreter;
use super::NaslValue;
use super::Result;

use super::InterpreterErrorKind as ErrorKind;

fn convert_value_to_array(val: &mut NaslValue, idx: usize) {
    let mut temp = NaslValue::Null;
    std::mem::swap(&mut temp, val);
    let mut arr = match temp {
        NaslValue::Array(x) => x,
        val => {
            vec![val]
        }
    };

    for _ in arr.len()..idx + 1 {
        arr.push(NaslValue::Null)
    }
    *val = NaslValue::Array(arr);
}

fn convert_value_to_dict(val: &mut NaslValue, index: &str) {
    let mut temp = NaslValue::Null;
    std::mem::swap(&mut temp, val);
    let mut dict = match temp {
        NaslValue::Array(x) => x
            .into_iter()
            .enumerate()
            .map(|(i, v)| (i.to_string(), v))
            .collect(),
        NaslValue::Dict(x) => x,
        NaslValue::Null => HashMap::new(),
        x => HashMap::from([("0".to_string(), x)]),
    };
    if !dict.contains_key(index) {
        dict.insert(index.to_string(), NaslValue::Null);
    }
    *val = NaslValue::Dict(dict);
}

fn assign(
    lhs: &mut NaslValue,
    indices: &[NaslValue],
    modify: impl FnOnce(&mut NaslValue) -> Result<NaslValue, ExprError>,
) -> Result<NaslValue, ExprError> {
    match indices.first() {
        Some(index) => {
            // We implicitly convert the lhs into whatever type
            // we need depending on the index.
            let str_index = index.as_string();
            let should_be_dict = str_index.is_ok() || lhs.is_dict();
            if should_be_dict {
                let index = index.to_string();
                convert_value_to_dict(lhs, &index);
                let lhs = lhs.as_dict_mut().unwrap().get_mut(&index).unwrap();
                assign(lhs, &indices[1..], modify)
            } else {
                let index = index.as_number().map_err(ExprError::both)? as usize;
                convert_value_to_array(lhs, index);
                let lhs = &mut lhs.as_array_mut().unwrap()[index];
                assign(lhs, &indices[1..], modify)
            }
        }
        None => modify(lhs),
    }
}

impl Interpreter<'_> {
    async fn eval_place_expr<'a>(
        &mut self,
        place_expr: &'a PlaceExpr,
    ) -> Result<(Option<Var<'a>>, Vec<NaslValue>)> {
        let var = self.register.get(place_expr.ident.to_str());
        let indices = self.collect_exprs(place_expr.array_accesses.iter()).await?;
        Ok((var, indices))
    }

    pub(crate) async fn resolve_assignment(&mut self, assignment: &Assignment) -> Result {
        let rhs = self.resolve_expr(&assignment.rhs).await?;
        let (var, indices) = self.eval_place_expr(&assignment.lhs).await?;
        // match instead of unwrap_or to make returning errors easier.
        let var = match var {
            None => {
                // If the variable could not be found in the current scope,
                // we implicitly declare a new variable in the innermost scope
                // and leave it uninitialized for now.
                if let AssignmentOperatorKind::Equal = assignment.op.kind {
                    self.register.add_local(
                        assignment.lhs.ident.to_str(),
                        RuntimeValue::Value(NaslValue::Null),
                    )
                }
                // Otherwise, we return an error.
                else {
                    return Err(
                        ErrorKind::AssignmentToUndefinedVar(assignment.lhs.ident.clone())
                            .with_span(&assignment.lhs.ident),
                    );
                }
            }
            Some(var) => var,
        };
        let val_mut = self
            .register
            .get_val_mut(var)
            .as_value_mut()
            .map_err(|e| e.with_span(&assignment.lhs.ident))?;
        use AssignmentOperatorKind::*;
        let modify = |lhs: &mut NaslValue| -> Result<NaslValue, ExprError> {
            *lhs = match assignment.op.kind {
                Equal => Ok(rhs),
                PlusEqual => Ok(lhs.add(rhs)),
                MinusEqual => Ok(lhs.sub(rhs)),
                StarEqual => lhs.mul(rhs),
                SlashEqual => lhs.div(rhs),
                PercentEqual => lhs.rem(rhs),
                LessLessEqual => lhs.shl(rhs),
                GreaterGreaterEqual => lhs.shr(rhs),
                GreaterGreaterGreaterEqual => lhs.shr_unsigned(rhs),
            }?;
            Ok(lhs.clone())
        };
        let val = assign(val_mut, &indices, modify).map_err(|e| {
            let span = match e.location {
                ExprLocation::Lhs => assignment.lhs.span(),
                ExprLocation::Rhs => assignment.rhs.span(),
                ExprLocation::Both => unreachable!(),
            };
            e.kind.with_span(&span)
        })?;
        if assignment.lhs.negate {
            Ok(val.not().map_err(|e| e.with_span(&*assignment.rhs))?)
        } else {
            Ok(val)
        }
    }

    pub(crate) async fn resolve_increment(&mut self, increment: &Increment) -> Result {
        let (var, indices) = self.eval_place_expr(&increment.expr).await?;
        let var = var.ok_or_else(|| {
            ErrorKind::AssignmentToUndefinedVar(increment.expr.ident.clone())
                .with_span(&increment.expr.ident)
        })?;
        let val_mut = self
            .register
            .get_val_mut(var)
            .as_value_mut()
            .map_err(|e| e.with_span(&increment.expr.ident))?;
        let modify = |val: &mut NaslValue| -> Result<NaslValue, ExprError> {
            let previous_value = val.clone();
            *val = match increment.op.kind {
                IncrementOperatorKind::PlusPlus => val.add(NaslValue::Number(1)),
                IncrementOperatorKind::MinusMinus => val.sub(NaslValue::Number(1)),
            };
            match increment.kind {
                IncrementKind::Prefix => Ok(val.clone()),
                IncrementKind::Postfix => Ok(previous_value),
            }
        };
        assign(val_mut, &indices, modify).map_err(|e| e.kind.with_span(&increment.expr.ident))
    }
}

#[cfg(test)]
mod tests {
    use crate::interpreter_test_ok;
    use crate::nasl::test_prelude::*;
    use std::collections::HashMap;

    #[test]
    fn variables() {
        let mut t = TestBuilder::default();
        t.ok("a = 12;", 12);
        t.ok("a += 13;", 25);
        t.ok("a -= 2;", 23);
        t.ok("a /= 2;", 11);
        t.ok("a *= 2;", 22);
        t.ok("a >>= 2;", 5);
        t.ok("a <<= 2;", 20);
        t.ok("a >>>= 2;", 5);
        t.ok("a %= 2;", 1);
        t.ok("a++;", 1);
        t.ok("++a;", 3);
        t.ok("a--;", 3);
        t.ok("--a;", 1);
    }

    #[test]
    fn unsigned_shift_operator() {
        let mut t = TestBuilder::default();
        t.ok("a = -5;", -5);
        t.ok("a >>= 2;", -2);
        t.ok("a = -5;", -5);
        t.ok("a >>>= 2;", 1073741822);
    }

    interpreter_test_ok!(basic_assign, "a = 12; a + 3;", 12, 15);

    interpreter_test_ok!(
        implicit_extend,
        "a[2] = 12; a;",
        12,
        NaslValue::Array(vec![NaslValue::Null, NaslValue::Null, 12.into()])
    );

    interpreter_test_ok!(
        implicit_transformation,
        "a = 12; a; a[2] = 12; a;",
        12,
        12,
        12,
        NaslValue::Array(vec![12.into(), NaslValue::Null, 12.into()])
    );

    interpreter_test_ok!(
        dict,
        "a['hi'] = 12; a; a['hi'];",
        12,
        NaslValue::Dict(HashMap::from([("hi".to_string(), 12.into())])),
        12
    );

    interpreter_test_ok!(array_creation, "a = [1, 2, 3];", vec![1, 2, 3]);

    interpreter_test_ok!(assign_negate, "!a = FALSE;", true);

    #[test]
    fn multidimensional_array() {
        let mut t = TestBuilder::default();
        t.ok(
            "a = [[1,2,3], [4,5,6], [7,8,9]];",
            vec![
                NaslValue::Array(vec![
                    NaslValue::Number(1),
                    NaslValue::Number(2),
                    NaslValue::Number(3),
                ]),
                NaslValue::Array(vec![
                    NaslValue::Number(4),
                    NaslValue::Number(5),
                    NaslValue::Number(6),
                ]),
                NaslValue::Array(vec![
                    NaslValue::Number(7),
                    NaslValue::Number(8),
                    NaslValue::Number(9),
                ]),
            ],
        );
        t.ok("a[0][0];", 1);
        t.ok("a[0][1];", 2);
        t.ok("a[0][2];", 3);
        t.ok("a[1][0];", 4);
        t.ok("a[1][1];", 5);
        t.ok("a[1][2];", 6);
        t.ok("a[2][0];", 7);
        t.ok("a[2][1];", 8);
        t.ok("a[2][2];", 9);
        t.ok("a[1][2] = 1000;", 1000);
        t.ok("a[2][2]++;", 9);
        t.ok("++a[2][2];", 11);
        t.ok("a[0][0];", 1);
        t.ok("a[0][1];", 2);
        t.ok("a[0][2];", 3);
        t.ok("a[1][0];", 4);
        t.ok("a[1][1];", 5);
        t.ok("a[1][2];", 1000);
        t.ok("a[2][0];", 7);
        t.ok("a[2][1];", 8);
        t.ok("a[2][2];", 11);
    }
}
