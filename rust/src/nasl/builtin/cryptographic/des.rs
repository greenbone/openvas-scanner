// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::nasl::{prelude::*, utils::function::StringOrData};
use aes::cipher::BlockEncrypt;
use ccm::KeyInit;
use des::cipher::generic_array::GenericArray;

#[nasl_function(named(key, data))]
fn encrypt_des(key: StringOrData, data: StringOrData) -> Result<Vec<u8>, FnError> {
    let key = key.data();
    if key.len() != 8 {
        return Err(ArgumentError::WrongArgument(format!(
            "key of len {} bytes, but expected 8 bytes",
            key.len()
        ))
        .into());
    }
    let mut data = GenericArray::clone_from_slice(data.data());
    let des_cipher = des::Des::new(&GenericArray::clone_from_slice(key));
    des_cipher.encrypt_block(&mut data);
    Ok(data.to_vec())
}

pub struct Des;

function_set! {
    Des,
    (
        (encrypt_des, "DES"),
    )
}
