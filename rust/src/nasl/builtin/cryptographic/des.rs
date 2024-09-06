// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::{
    function_set,
    nasl::utils::{Context, FunctionErrorKind, Register},
};
use aes::cipher::BlockEncrypt;
use ccm::KeyInit;
use des::cipher::generic_array::GenericArray;

fn encrypt_des(
    register: &Register,
    _: &Context,
) -> Result<crate::nasl::syntax::NaslValue, FunctionErrorKind> {
    let positional = register.positional();
    if positional.len() != 2 {
        return Err(FunctionErrorKind::MissingPositionalArguments {
            expected: 2,
            got: positional.len(),
        });
    }
    let key = match &positional[1] {
        crate::nasl::syntax::NaslValue::Data(x) => x,
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
        crate::nasl::syntax::NaslValue::Data(x) => x,
        _ => {
            return Err(FunctionErrorKind::WrongArgument(
                "expected Data.".to_string(),
            ))
        }
    });
    let des_cipher = des::Des::new(&GenericArray::clone_from_slice(key));
    des_cipher.encrypt_block(&mut data);
    Ok(data.to_vec().into())
}

pub struct Des;

function_set! {
    Des,
    sync_stateless,
    (
        (encrypt_des, "DES"),
    )
}
