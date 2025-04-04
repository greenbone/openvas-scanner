// SPDX-FileCopyrightText: 2024 Greenbone AG
//

// SPDX-License-Identifier: GPL-2.0-or-later
use crate::function_set;
use crate::nasl::ArgumentError;
use crate::nasl::prelude::*;
use crate::nasl::utils::function::StringOrData;
use dsa::SigningKey;
use nasl_function_proc_macro::nasl_function;
use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey, traits::PrivateKeyParts};

#[nasl_function(named(passphrase))]
fn pem_to_rsa(register: &Register, passphrase: String) -> Result<NaslValue, FnError> {
    let ori_pem = StringOrData::from_nasl_value(register.nasl_value("priv")?).map(|s| s.0)?;
    let decrypted_key = match RsaPrivateKey::from_pkcs8_encrypted_pem(&ori_pem, passphrase) {
        Ok(x) => x,
        Err(e) => return Err(ArgumentError::WrongArgument(format!("{e}")).into()),
    };
    let priv_exp = decrypted_key.d();
    Ok(NaslValue::Data(priv_exp.to_bytes_be()))
}

#[nasl_function(named(passphrase))]
fn pem_to_dsa(register: &Register, passphrase: String) -> Result<NaslValue, FnError> {
    let ori_pem = StringOrData::from_nasl_value(register.nasl_value("priv")?).map(|s| s.0)?;
    let decrypted_key = match SigningKey::from_pkcs8_encrypted_pem(&ori_pem, passphrase) {
        Ok(x) => x,
        Err(e) => return Err(ArgumentError::WrongArgument(format!("{e}")).into()),
    };
    Ok(NaslValue::Data(decrypted_key.x().to_bytes_be()))
}

pub struct PemTo;
function_set! {
    PemTo,
    (
        (pem_to_rsa, "pem_to_rsa"),
        (pem_to_dsa, "pem_to_dsa"),
    )
}
