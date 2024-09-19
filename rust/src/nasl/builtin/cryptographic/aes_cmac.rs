// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::nasl::syntax::NaslValue;
use crate::nasl::utils::error::GeneralErrorType;
use crate::nasl::utils::{Context, FunctionErrorKind, Register};
use aes::Aes128;
use cmac::{Cmac, Mac};

use crate::function_set;

use super::{get_data, get_key};

/// NASL function to calculate CMAC wit AES128.
///
/// This function expects 2 named arguments key and data either in a string or data type.
/// It is important to notice, that internally the CMAC algorithm is used and not, as the name
/// suggests, CBC-MAC.
fn aes_cmac(register: &Register, _: &Context) -> Result<NaslValue, FunctionErrorKind> {
    let key = get_key(register)?;
    let data = get_data(register)?;

    let mut mac = Cmac::<Aes128>::new_from_slice(key)
        .map_err(|e| GeneralErrorType::UnexpectedData(format!("CMAC: {}", e)))?;
    mac.update(data);

    Ok(mac.finalize().into_bytes().to_vec().into())
}

pub struct AesCmac;

function_set! {
    AesCmac,
    sync_stateless,
    (
        (aes_cmac, "aes_mac_cbc"),
        aes_cmac,
    )
}
