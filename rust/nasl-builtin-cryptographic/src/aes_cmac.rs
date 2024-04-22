// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use aes::Aes128;
use cmac::{Cmac, Mac};
use nasl_builtin_utils::error::GeneralErrorType;
use nasl_builtin_utils::{Context, FunctionErrorKind, Register};
use nasl_syntax::NaslValue;

use crate::{get_data, get_key, NaslFunction};

/// NASL function to calculate CMAC wit AES128.
///
/// This function expects 2 named arguments key and data either in a string or data type.
/// It is important to notice, that internally the CMAC algorithm is used and not, as the name
/// suggests, CBC-MAC.
fn aes_cmac<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let key = get_key(register)?;
    let data = get_data(register)?;

    let mut mac = Cmac::<Aes128>::new_from_slice(key)
        .map_err(|e| GeneralErrorType::UnexpectedData(format!("CMAC: {}", e)))?;
    mac.update(data);

    Ok(mac.finalize().into_bytes().to_vec().into())
}

pub fn lookup<K>(key: &str) -> Option<NaslFunction<K>> {
    match key {
        "aes_mac_cbc" => Some(aes_cmac),
        "aes_cmac" => Some(aes_cmac),
        _ => None,
    }
}
