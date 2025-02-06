// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::nasl::prelude::*;
use aes::cipher::BlockEncrypt;
use ccm::KeyInit;
use des::cipher::generic_array::GenericArray;

#[nasl_function]
fn encrypt_des(register: &Register) -> Result<NaslValue, FnError> {
    let positional = register.positional();
    if positional.len() != 2 {
        return Err(ArgumentError::MissingPositionals {
            expected: 2,
            got: positional.len(),
        }
        .into());
    }
    let key = match &positional[1] {
        NaslValue::Data(x) => x,
        _ => return Err(ArgumentError::WrongArgument("expected Data.".to_string()).into()),
    };
    if key.len() != 8 {
        return Err(
            ArgumentError::WrongArgument("16, 32 or 48 bytes length key".to_string()).into(),
        );
    }
    let mut data = GenericArray::clone_from_slice(match &positional[0] {
        NaslValue::Data(x) => x,
        _ => return Err(ArgumentError::WrongArgument("expected Data.".to_string()).into()),
    });
    let des_cipher = des::Des::new(&GenericArray::clone_from_slice(key));
    des_cipher.encrypt_block(&mut data);
    Ok(data.to_vec().into())
}

pub struct Des;

function_set! {
    Des,
    (
        (encrypt_des, "DES"),
    )
}
