// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::HashMap;

use crate::nasl::syntax::parser::grammar::Assignment;
use crate::nasl::syntax::parser::grammar::AssignmentOperator;

use super::InterpretErrorKind;
use super::interpreter::Interpreter;
use super::interpreter::Result;
use crate::nasl::syntax::NaslValue;
use crate::nasl::utils::ContextType;

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
    rhs: NaslValue,
    op: AssignmentOperator,
) -> Result {
    use AssignmentOperator::*;
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
                assign(lhs, &indices[1..], rhs, op)
            } else {
                let index = index.as_number()? as usize;
                convert_value_to_array(lhs, index);
                let lhs = &mut lhs.as_array_mut().unwrap()[index];
                assign(lhs, &indices[1..], rhs, op)
            }
        }
        None => {
            *lhs = match op {
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
        }
    }
}

impl Interpreter<'_> {
    // #[allow(clippy::too_many_arguments)]
    // fn handle_dict(
    //     &mut self,
    //     ridx: usize,
    //     key: &str,
    //     idx: String,
    //     left: NaslValue,
    //     right: &NaslValue,
    //     return_original: &AssignOrder,
    //     result: impl Fn(&NaslValue, &NaslValue) -> NaslValue,
    // ) -> NaslValue {
    //     let mut dict = prepare_dict(left);
    //     match return_original {
    //         AssignOrder::ReturnAssign => {
    //             let original = dict.get(&idx).unwrap_or(&NaslValue::Null).clone();
    //             let result = result(&original, right);
    //             dict.insert(idx, result);
    //             self.save(ridx, key, NaslValue::Dict(dict));
    //             original
    //         }
    //         AssignOrder::AssignReturn => {
    //             let original = dict.get(&idx).unwrap_or(&NaslValue::Null);
    //             let result = result(original, right);
    //             dict.insert(idx, result.clone());
    //             self.save(ridx, key, NaslValue::Dict(dict));
    //             result
    //         }
    //     }
    // }

    // #[allow(clippy::too_many_arguments)]
    // fn handle_array(
    //     &mut self,
    //     ridx: usize,
    //     key: &str,
    //     idx: &NaslValue,
    //     left: NaslValue,
    //     right: &NaslValue,
    //     return_original: &AssignOrder,
    //     result: impl Fn(&NaslValue, &NaslValue) -> NaslValue,
    // ) -> NaslValue {
    //     let (idx, mut arr) = prepare_array(idx, left);
    //     match return_original {
    //         AssignOrder::ReturnAssign => {
    //             let orig = arr[idx].clone();
    //             let result = result(&orig, right);
    //             arr[idx] = result;
    //             self.save(ridx, key, NaslValue::Array(arr));
    //             orig
    //         }
    //         AssignOrder::AssignReturn => {
    //             let result = result(&arr[idx], right);
    //             arr[idx] = result.clone();
    //             self.save(ridx, key, NaslValue::Array(arr));
    //             result
    //         }
    //     }
    // }

    /// Assign a right value to a left value. Return either the
    /// previous or the new value, based on the order.
    pub(crate) async fn resolve_assignment(&mut self, assignment: &Assignment) -> Result {
        let rhs = self.resolve_expr(&assignment.rhs).await?;
        let var = self.register.get(&assignment.lhs.ident.0);
        let indices = self
            .collect_exprs(assignment.lhs.array_accesses.iter())
            .await?;
        // match instead of unwrap_or to make returning errors easier.
        let var = match var {
            None => {
                // If the variable could not be found in the current scope,
                // we implicitly declare a new variable in the innermost scope
                // and leave it uninitialized for now.
                if let AssignmentOperator::Equal = assignment.op {
                    self.register
                        .add_local(&assignment.lhs.ident.0, ContextType::Value(NaslValue::Null))
                }
                // Otherwise, we return an error.
                else {
                    return Err(InterpretErrorKind::AssignmentToUndefinedVar(
                        assignment.lhs.ident.clone(),
                    )
                    .into());
                }
            }
            Some(var) => var,
        };
        let val_mut = self.register.get_val_mut(var);
        match val_mut {
            ContextType::Function(_, _) => Err(InterpretErrorKind::FunctionExpectedValue)?,
            ContextType::Value(val) => assign(val, &indices, rhs, assignment.op),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::interpreter_test;
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

    interpreter_test!(basic_assign, "a = 12; a + 3;", 12, 15);

    interpreter_test!(
        implicit_extend,
        "a[2] = 12; a;",
        12,
        NaslValue::Array(vec![NaslValue::Null, NaslValue::Null, 12.into()])
    );

    interpreter_test!(
        implicit_transformation,
        "a = 12; a; a[2] = 12; a;",
        12,
        12,
        12,
        NaslValue::Array(vec![12.into(), NaslValue::Null, 12.into()])
    );

    interpreter_test!(
        dict,
        "a['hi'] = 12; a; a['hi'];",
        12,
        NaslValue::Dict(HashMap::from([("hi".to_string(), 12.into())])),
        12
    );

    interpreter_test!(array_creation, "a = [1, 2, 3];", vec![1, 2, 3]);

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
        t.ok("a[0][0];", 1);
        t.ok("a[0][1];", 2);
        t.ok("a[0][2];", 3);
        t.ok("a[1][0];", 4);
        t.ok("a[1][1];", 5);
        t.ok("a[1][2];", 1000);
        t.ok("a[2][0];", 7);
        t.ok("a[2][1];", 8);
        t.ok("a[2][2];", 9);
    }
}
