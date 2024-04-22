// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::NaslFunction;

/// NASL function to calculate GMAC with AES128.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
#[cfg(feature = "nasl-c-lib")]
fn aes_gmac<K>(
    register: &nasl_builtin_utils::Register,
    _: &nasl_builtin_utils::Context<K>,
) -> Result<nasl_syntax::NaslValue, nasl_builtin_utils::FunctionErrorKind> {
    use crate::{get_data, get_iv, get_key};
    use nasl_c_lib::cryptographic::mac::aes_gmac;

    let key = get_key(register)?;
    let data = get_data(register)?;
    let iv = get_iv(register)?;

    match aes_gmac(data, key, iv) {
        Ok(val) => Ok(val.into()),
        Err(code) => Err(nasl_builtin_utils::FunctionErrorKind::GeneralError(
            nasl_builtin_utils::error::GeneralErrorType::UnexpectedData(format!(
                "Error code {}",
                code
            )),
        )),
    }
}

#[cfg(feature = "nasl-c-lib")]
pub fn lookup<K>(key: &str) -> Option<NaslFunction<K>> {
    match key {
        "aes_mac_gcm" => Some(aes_gmac),
        "aes_gmac" => Some(aes_gmac),
        _ => None,
    }
}

#[cfg(not(feature = "nasl-c-lib"))]
pub fn lookup<K>(_: &str) -> Option<NaslFunction<K>> {
    None
}
