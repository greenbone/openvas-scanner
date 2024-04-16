// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use aes::cipher::BlockEncrypt;
use ccm::KeyInit;
use des::cipher::generic_array::GenericArray;
use nasl_builtin_utils::{Context, FunctionErrorKind, NaslFunction, Register};

fn encrypt_des<K>(
    register: &Register,
    _: &Context<K>,
) -> Result<nasl_syntax::NaslValue, FunctionErrorKind> {
    let positional = register.positional();
    if positional.len() != 2 {
        return Err(FunctionErrorKind::MissingPositionalArguments {
            expected: 2,
            got: positional.len(),
        });
    }
    let key = match &positional[1] {
        nasl_syntax::NaslValue::Data(x) => x,
        _ => {
            return Err(FunctionErrorKind::WrongArgument(
                "expected Data.".to_string(),
            ))
        }
    };
    if key.len() != 8 {
        return Err(FunctionErrorKind::WrongArgument(
            "16, 32 or 48 bytes length key".to_string(),
        ));
    }
    let mut data = GenericArray::clone_from_slice(match &positional[0] {
        nasl_syntax::NaslValue::Data(x) => x,
        _ => {
            return Err(FunctionErrorKind::WrongArgument(
                "expected Data.".to_string(),
            ))
        }
    });
    let des_cipher = des::Des::new(&GenericArray::clone_from_slice(key));
    des_cipher.encrypt_block(&mut data);
    return Ok(data.to_vec().into());
}
pub fn lookup<K>(key: &str) -> Option<NaslFunction<K>> {
    match key {
        "DES" => Some(encrypt_des),
        _ => None,
    }
}
