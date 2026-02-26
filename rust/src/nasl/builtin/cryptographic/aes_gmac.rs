// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::function_set;
use crate::nasl::{prelude::*, utils::function::StringOrData};

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
#[nasl_function(named(key, iv, data))]
fn nasl_aes_gmac(
    key: StringOrData,
    iv: StringOrData,
    data: StringOrData,
) -> Result<NaslValue, FnError> {
    aes_gmac(data.data(), key.data(), iv.data())
}

pub struct AesGmac;

function_set! {
    AesGmac,
    (
        (nasl_aes_gmac, "aes_mac_gcm"),
    )
}
