// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use aes::Aes128;
use cmac::{Cmac, Mac};

use crate::nasl::prelude::*;

use super::{get_data, get_key, CryptographicError};

/// NASL function to calculate CMAC wit AES128.
///
/// This function expects 2 named arguments key and data either in a string or data type.
/// It is important to notice, that internally the CMAC algorithm is used and not, as the name
/// suggests, CBC-MAC.
#[nasl_function]
fn aes_cmac(register: &Register) -> Result<NaslValue, FnError> {
    let key = get_key(register)?;
    let data = get_data(register)?;

    let mut mac =
        Cmac::<Aes128>::new_from_slice(key).map_err(CryptographicError::AesCmacInvalidLength)?;
    mac.update(data);

    Ok(mac.finalize().into_bytes().to_vec().into())
}

pub struct AesCmac;

function_set! {
    AesCmac,
    (
        (aes_cmac, "aes_mac_cbc"),
        aes_cmac,
    )
}
