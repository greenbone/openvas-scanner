// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::function_set;
#[cfg(feature = "nasl-c-lib")]
use crate::nasl::prelude::*;

#[cfg(feature = "nasl-c-lib")]
pub fn aes_gmac(data: &[u8], key: &[u8], iv: &[u8]) -> Result<NaslValue, FnError> {
    use nasl_c_lib::cryptographic::mac::aes_gmac;

    use crate::nasl::builtin::cryptographic::CryptographicError;

    match aes_gmac(data, key, iv) {
        Ok(val) => Ok(val.into()),
        Err(msg) => Err(CryptographicError::AesGmacError(msg.into()).into()),
    }
}

/// NASL function to calculate GMAC with AES128.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
#[cfg(feature = "nasl-c-lib")]
#[nasl_function]
fn nasl_aes_gmac(register: &Register) -> Result<NaslValue, FnError> {
    use super::{get_data, get_iv, get_key};

    let key = get_key(register)?;
    let data = get_data(register)?;
    let iv = get_iv(register)?;

    aes_gmac(data, key, iv)
}

pub struct AesGmac;

#[cfg(feature = "nasl-c-lib")]
function_set! {
    AesGmac,
    (
        (nasl_aes_gmac, "aes_mac_gcm"),
    )
}

#[cfg(not(feature = "nasl-c-lib"))]
function_set! {
    AesGmac,
    (
    )
}
