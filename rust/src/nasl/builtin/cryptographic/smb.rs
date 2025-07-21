// SPDX-FileCopyrightText: 2024 Greenbone AG
//

// SPDX-License-Identifier: GPL-2.0-or-later
use crate::function_set;
use crate::nasl::builtin::cryptographic::CryptographicError;
use crate::nasl::{FnError, NaslValue};
use aes::Aes128;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use cmac::Cmac;
use cmac::Mac;
use digest::InvalidLength;
use hmac::Hmac;
use nasl_function_proc_macro::nasl_function;
use sha2::Sha256;

#[nasl_function(named(key, buf))]
fn smb_cmac_aes_signature(key: &str, buf: &str) -> Result<NaslValue, FnError> {
    let key_bytes = key.as_bytes();
    let buf_bytes = buf.as_bytes();
    let mut cmac_obj = <Cmac<Aes128> as KeyInit>::new_from_slice(key_bytes)
        .map_err(|e| CryptographicError::Smb(e.to_string()))?;
    Mac::update(&mut cmac_obj, buf_bytes);
    let finish = cmac::Mac::finalize(cmac_obj).into_bytes();
    Ok(finish.to_vec().into())
}

#[nasl_function(named(key, buf, iv))]
fn smb_gmac_aes_signature(key: &str, buf: &str, iv: &str) -> Result<NaslValue, FnError> {
    let key_bytes = key.as_bytes();
    let buf_bytes = buf.as_bytes();
    let iv_bytes = iv.as_bytes();
    let gmac = Aes128Gcm::new_from_slice(key_bytes).unwrap();
    let nonce = Nonce::from_slice(iv_bytes);
    let auth = gmac.encrypt(nonce, buf_bytes.as_ref()).unwrap();
    Ok(auth.into())
}
#[nasl_function(named(key, label, ctx, lvalue))]
fn smb3kdf(
    key: &str,
    label: &str,
    ctx: &str,
    lvalue: usize,
) -> Result<NaslValue, CryptographicError> {
    let key_bytes = key.as_bytes();
    let label_bytes = label.as_bytes();
    let ctx_bytes = ctx.as_bytes();
    let mut mac_obj = match <Hmac<Sha256> as KeyInit>::new_from_slice(key_bytes) {
        Ok(x) => x,
        Err(InvalidLength) => {
            return Err(CryptographicError::Smb("invalid key length".into()));
        }
    };
    if lvalue != 128 && lvalue != 256 {
        return Err(CryptographicError::Smb(format!(
            "invalid key length: expected 128 or 256, got {}",
            lvalue
        )));
    }
    let buflen = 4 + label_bytes.len() + 1 + ctx_bytes.len() + 4;
    let mut buf = Vec::with_capacity(buflen);

    buf.extend_from_slice(&1u32.to_be_bytes());
    buf.extend_from_slice(label_bytes);
    buf.push(0);
    buf.extend_from_slice(ctx_bytes);
    buf.extend_from_slice(&lvalue.to_be_bytes());
    mac_obj.update(&buf);
    let result = mac_obj.finalize().into_bytes();
    let resultlen = (lvalue / 8) as usize;
    Ok(result[..resultlen].into())
}

pub struct Smb;
function_set! {
    Smb,
    (
        (smb_gmac_aes_signature, "smb_gmac_aes_signature"),
        (smb_cmac_aes_signature, "smb_cmac_aes_signature"),
        (smb3kdf, "smb3kdf"),
    )
}
