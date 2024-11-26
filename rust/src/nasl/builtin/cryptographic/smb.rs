// SPDX-FileCopyrightText: 2024 Greenbone AG
//

// SPDX-License-Identifier: GPL-2.0-or-later
use crate::function_set;
use crate::nasl::FunctionErrorKind;
use crate::nasl::NaslValue;
use aes::Aes128;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use cmac::Cmac;
use digest::Update;
use nasl_function_proc_macro::nasl_function;

#[nasl_function(named(key, buf))]
fn smb_cmac_aes_signature(key: &str, buf: &str) -> Result<NaslValue, FunctionErrorKind> {
    let key_bytes = key.as_bytes();
    let buf_bytes = buf.as_bytes();
    let mut cmac = Cmac::<Aes128>::new_from_slice(&key_bytes)
        .map_err(|e| FunctionErrorKind::Diagnostic(e.to_string(), None))?;
    cmac.update(buf_bytes);
    let finish = cmac::Mac::finalize(cmac).into_bytes();
    Ok(finish.to_vec().into())
}

#[nasl_function(named(key, buf, iv))]
fn smb_gmac_aes_signature(key: &str, buf: &str, iv: &str) -> Result<NaslValue, FunctionErrorKind> {
    let key_bytes = key.as_bytes();
    let buf_bytes = buf.as_bytes();
    let iv_bytes = iv.as_bytes();
    let gmac = Aes128Gcm::new_from_slice(&key_bytes).unwrap();
    let nonce = Nonce::from_slice(&iv_bytes);
    let auth = gmac.encrypt(nonce, buf_bytes.as_ref()).unwrap();
    Ok(auth.into())
}

pub struct Smb;
function_set! {
    Smb,
    sync_stateless,
    (
        (smb_gmac_aes_signature, "smb_gmac_aes_signature"),
        (smb_cmac_aes_signature, "smb_cmac_aes_signature"),
    )
}
