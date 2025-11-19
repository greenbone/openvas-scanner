// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use aes::Aes128;
use cmac::{Cmac, Mac};

use crate::nasl::prelude::*;

use super::CryptographicError;

pub fn aes_cmac(key: &[u8], data: &[u8]) -> Result<NaslValue, FnError> {
    let mut mac =
        Cmac::<Aes128>::new_from_slice(key).map_err(CryptographicError::AesCmacInvalidLength)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec().into())
}

/// NASL function to calculate CMAC wit AES128.
///
/// This function expects 2 named arguments key and data either in a string or data type.
/// It is important to notice, that internally the CMAC algorithm is used and not, as the name
/// suggests, CBC-MAC.
#[nasl_function(named(key, data))]
fn nasl_aes_cmac(key: &[u8], data: &[u8]) -> Result<NaslValue, FnError> {
    aes_cmac(key, data)
}

pub struct AesCmac;

function_set! {
    AesCmac,
    (
        (nasl_aes_cmac, "aes_mac_cbc"),
        (nasl_aes_cmac, "aes_mac"),
    )
}
