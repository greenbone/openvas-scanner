// SPDX-FileCopyrightText: 2024 Greenbone AG
//

// SPDX-License-Identifier: GPL-2.0-or-later
use crate::function_set;
use crate::nasl::prelude::*;
use dsa::SigningKey;
use nasl_function_proc_macro::nasl_function;
use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey, traits::PrivateKeyParts};

use super::CryptographicError;

fn get_priv(register: &Register) -> Result<String, CryptographicError> {
    // using register because priv is a rust word
    match register.named("priv") {
        Some(ContextType::Value(NaslValue::String(x))) => Ok(x.to_string()),
        Some(ContextType::Value(NaslValue::Data(x))) => {
            Ok(x.iter().map(|x| *x as char).collect::<String>())
        }
        _ => Err(CryptographicError::Rsa("invalid key".to_string())),
    }
}

#[nasl_function(named(passphrase))]
fn pem_to_rsa(register: &Register, passphrase: String) -> Result<NaslValue, CryptographicError> {
    let ori_pem = get_priv(register)?;
    let decrypted_key = RsaPrivateKey::from_pkcs8_encrypted_pem(&ori_pem, passphrase).unwrap();
    let priv_exp = decrypted_key.d();
    Ok(NaslValue::Data(priv_exp.to_bytes_be()))
}

#[nasl_function(named(passphrase))]
fn pem_to_dsa(register: &Register, passphrase: String) -> Result<NaslValue, CryptographicError> {
    let ori_pem = get_priv(register)?;
    let decrypted_key = SigningKey::from_pkcs8_encrypted_pem(&ori_pem, passphrase).unwrap();
    Ok(NaslValue::Data(decrypted_key.x().to_bytes_be()))
}

pub struct PemTo;
function_set! {
    PemTo,
    (
        (pem_to_rsa,"pem_to_rsa"),
        (pem_to_dsa,"pem_to_dsa"),
    )
}
